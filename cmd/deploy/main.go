// deploy is the shared local/CI deployment entrypoint. It never applies from preview/build.
package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/term"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type runner interface {
	Run(string, []string, []string, io.Reader) ([]byte, error)
}
type commandRunner struct{ Dir string }

func (r commandRunner) Run(name string, args, env []string, in io.Reader) ([]byte, error) {
	c := exec.Command(name, args...)
	c.Dir = r.Dir
	c.Env = append(os.Environ(), env...)
	c.Stdin = in
	var out bytes.Buffer
	c.Stdout = &out
	c.Stderr = &out
	e := c.Run()
	if e != nil {
		return nil, fmt.Errorf("%s failed: %w: %s", name, e, out.String())
	}
	return out.Bytes(), nil
}

type configData struct {
	Version                                                             int
	Environment, Profile, Account, Region, Backend, Repository, RoleARN string
}

var environmentRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,15}$`)

// in must be closable if it can block beyond timeout; closing prevents a leaked reader.
func confirm(in io.Reader, out io.Writer, timeout time.Duration) bool {
	fmt.Fprintln(out, "Deploy the previewed changes? [Y/n] Continuing in 5 seconds; press n or Ctrl+C to cancel.")
	answers := make(chan bool, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		s := bufio.NewReader(in)
		b, e := s.ReadByte()
		answers <- e == nil && (b == '\n' || b == '\r' || b == 'y' || b == 'Y')
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	remaining := 5
	for {
		select {
		case yes := <-answers:
			return yes
		case <-timer.C:
			if c, ok := in.(io.Closer); ok {
				c.Close()
				<-done
			}
			return true
		case <-tick.C:
			fmt.Fprintf(out, "%d...\n", remaining)
			remaining--
		}
	}
}
func seal(plain []byte, password string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, e := rand.Read(salt); e != nil {
		return nil, e
	}
	key, e := pbkdf2.Key(sha256.New, password, salt, 600000, 32)
	if e != nil {
		return nil, e
	}
	b, _ := aes.NewCipher(key)
	a, _ := cipher.NewGCM(b)
	nonce := make([]byte, a.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return nil, e
	}
	header := append([]byte("SIV1"), salt...)
	header = append(header, nonce...)
	return a.Seal(header, nonce, plain, header), nil
}
func openVault(data []byte, password string) ([]byte, error) {
	if len(data) < 48 || string(data[:4]) != "SIV1" {
		return nil, errors.New("invalid vault format")
	}
	key, e := pbkdf2.Key(sha256.New, password, data[4:20], 600000, 32)
	if e != nil {
		return nil, e
	}
	b, _ := aes.NewCipher(key)
	a, _ := cipher.NewGCM(b)
	p, e := a.Open(nil, data[20:32], data[32:], data[:32])
	if e != nil {
		return nil, errors.New("incorrect vault password or damaged vault; file preserved")
	}
	return p, e
}
func atomicWrite(path string, b []byte) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e != nil {
		f.Close()
		return e
	}
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(f.Name(), path)
}
func fingerprint(root, tool, scope string) (string, error) {
	mod, e := os.ReadFile(filepath.Join(root, "go.mod"))
	if e != nil {
		return "", e
	}
	for _, match := range regexp.MustCompile(`=>\s+([^\s]+)`).FindAllStringSubmatch(string(mod), -1) {
		target := strings.Trim(match[1], "\"")
		if strings.HasPrefix(target, ".") || filepath.IsAbs(target) {
			resolved := target
			if !filepath.IsAbs(resolved) {
				resolved = filepath.Join(root, resolved)
			}
			rel, e := filepath.Rel(root, resolved)
			if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return "", errors.New("external local module replacements are unsupported by the deployment cache")
			}
		}
	}
	type item struct{ Name, Hash string }
	m := []item{{"schema", "sworn-ink-build-v1"}, {"tool", tool}, {"target", "linux/arm64;GOARM64=v8.0;CGO_ENABLED=0;GOWORK=off;GOEXPERIMENT=;GOFLAGS=;GOTOOLCHAIN=local;-trimpath;zip-v1"}, {"scope", scope}}
	e = filepath.WalkDir(root, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		rel, _ := filepath.Rel(root, p)
		if d.IsDir() {
			if rel == ".git" || rel == "build" || rel == "infra" || rel == "cmd/deploy" || rel == ".deploy" {
				return filepath.SkipDir
			}
			return nil
		}
		b, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		h := sha256.Sum256(b)
		m = append(m, item{filepath.ToSlash(rel), hex.EncodeToString(h[:])})
		return nil
	})
	if e != nil {
		return "", e
	}
	sort.Slice(m, func(i, j int) bool { return m[i].Name < m[j].Name })
	b, _ := json.Marshal(m)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

type buildRecord struct{ Input, Artifact string }

func build(root, scope string, r runner, force bool) error {
	version, e := r.Run("go", []string{"version"}, nil, nil)
	if e != nil {
		return e
	}
	input, e := fingerprint(root, string(version), scope)
	if e != nil {
		return e
	}
	dir := filepath.Join(root, "build")
	if e = os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	lock, e := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return errors.New("build lock exists; inspect active deploy before manually removing build/.lock")
	}
	lock.Close()
	defer os.Remove(filepath.Join(dir, ".lock"))
	recordPath := filepath.Join(dir, "manifest.json")
	artifactPath := filepath.Join(dir, "bootstrap.zip")
	recordBytes, _ := os.ReadFile(recordPath)
	var old buildRecord
	json.Unmarshal(recordBytes, &old)
	archive, _ := os.ReadFile(artifactPath)
	hash := sha256.Sum256(archive)
	if !force && input == old.Input && len(archive) > 0 && hex.EncodeToString(hash[:]) == old.Artifact {
		fmt.Println("Reused verified Lambda artifact")
		return nil
	}
	binary := filepath.Join(dir, "bootstrap.tmp")
	defer os.Remove(binary)
	if _, e = r.Run("go", []string{"build", "-trimpath", "-o", binary, "./cmd/api"}, []string{"GOOS=linux", "GOARCH=arm64", "CGO_ENABLED=0", "GOFLAGS=", "GOWORK=off", "GOARM64=v8.0", "GOEXPERIMENT=", "GOTOOLCHAIN=local"}, nil); e != nil {
		return e
	}
	payload, e := os.ReadFile(binary)
	if e != nil {
		return e
	}
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	h := &zip.FileHeader{Name: "bootstrap", Method: zip.Deflate}
	h.SetMode(0755)
	h.Modified = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)
	w, e := z.CreateHeader(h)
	if e != nil {
		return e
	}
	if _, e = w.Write(payload); e != nil {
		return e
	}
	if e = z.Close(); e != nil {
		return e
	}
	if e = atomicWrite(artifactPath, buf.Bytes()); e != nil {
		return e
	}
	hash = sha256.Sum256(buf.Bytes())
	recordBytes, _ = json.Marshal(buildRecord{input, hex.EncodeToString(hash[:])})
	return atomicWrite(recordPath, recordBytes)
}

var inputReader = bufio.NewReader(os.Stdin)

func ask(label, defaultValue string) (string, error) {
	fmt.Printf("%s [%s]: ", label, defaultValue)
	v, e := inputReader.ReadString('\n')
	if e != nil {
		return "", errors.New("input closed; cancelled")
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return defaultValue, nil
	}
	return v, nil
}
func hidden(label string) (string, error) {
	fmt.Print(label + ": ")
	b, e := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	return string(b), e
}
func run() error {
	env := flag.String("environment", "", "dev, qa, prod or custom environment")
	action := flag.String("action", "preview", "setup, build, preview, deploy, status, reconfigure, recovery, github-plan, github-setup, oidc-plan, oidc-setup, boundary-plan, boundary-setup")
	approve := flag.Bool("approve", false, "explicit noninteractive deployment approval")
	noninteractive := flag.Bool("noninteractive", false, "require all saved/environment inputs")
	force := flag.Bool("force-rebuild", false, "ignore build cache")
	flag.Parse()
	root, e := os.Getwd()
	if e != nil {
		return e
	}
	for {
		if _, e = os.Stat(filepath.Join(root, "infra", "Pulumi.yaml")); e == nil {
			break
		}
		next := filepath.Dir(root)
		if next == root {
			return errors.New("run from the repository or its subdirectory")
		}
		root = next
	}
	interactive := !*noninteractive && term.IsTerminal(int(os.Stdin.Fd()))
	if *env == "" {
		if !interactive {
			return errors.New("--environment is required")
		}
		*env, e = ask("Environment (dev, qa, prod or custom)", "dev")
		if e != nil {
			return e
		}
	}
	if !environmentRE.MatchString(*env) {
		return errors.New("environment must contain 1..16 lowercase letters, digits or hyphens and start with a letter")
	}
	home, e := os.UserConfigDir()
	if e != nil {
		return e
	}
	dir := filepath.Join(home, "sworn-ink", *env)
	if e = os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	operation, lockErr := os.OpenFile(filepath.Join(dir, "operation.lock"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if lockErr != nil {
		return errors.New("another operation holds this environment lock; inspect before manually removing " + filepath.Join(dir, "operation.lock"))
	}
	fmt.Fprintln(operation, os.Getpid())
	operation.Close()
	defer os.Remove(filepath.Join(dir, "operation.lock"))
	path := filepath.Join(dir, "settings.json")
	var c configData
	b, readErr := os.ReadFile(path)
	if readErr == nil {
		if e = json.Unmarshal(b, &c); e != nil {
			return e
		}
		if c.Version != 1 || c.Environment != *env {
			return errors.New("incompatible settings scope")
		}
		fmt.Println("Configuration source: saved environment settings")
	} else if !os.IsNotExist(readErr) {
		return readErr
	}
	c.Version = 1
	c.Environment = *env
	fields := []struct {
		Name, Env string
		Target    *string
	}{{"AWS SSO profile", "AWS_PROFILE", &c.Profile}, {"AWS account", "DEPLOY_ACCOUNT", &c.Account}, {"AWS region", "AWS_REGION", &c.Region}, {"S3 state URL", "DEPLOY_BACKEND", &c.Backend}, {"GitHub repository owner/name", "DEPLOY_REPOSITORY", &c.Repository}, {"GitHub OIDC role ARN", "DEPLOY_ROLE_ARN", &c.RoleARN}}
	for _, f := range fields {
		if f.Env == "DEPLOY_BACKEND" && strings.HasPrefix(*action, "boundary-") {
			continue
		}
		if (f.Env == "DEPLOY_REPOSITORY" || f.Env == "DEPLOY_ROLE_ARN") && !strings.HasPrefix(*action, "github-") && !strings.HasPrefix(*action, "oidc-") {
			continue
		}
		if v, ok := os.LookupEnv(f.Env); ok {
			*f.Target = v
		}
		if *f.Target == "" || *action == "reconfigure" {
			if f.Env == "AWS_PROFILE" && !interactive {
				continue
			}
			if !interactive {
				if f.Env == "DEPLOY_REPOSITORY" || f.Env == "DEPLOY_ROLE_ARN" {
					continue
				}
				return fmt.Errorf("missing %s", f.Env)
			}
			*f.Target, e = ask(f.Name, *f.Target)
			if e != nil {
				return e
			}
		}
	}
	if !strings.HasPrefix(*action, "boundary-") && !regexp.MustCompile(`^s3://[a-z0-9.-]+/[a-zA-Z0-9/_-]+$`).MatchString(c.Backend) {
		return errors.New("state URL must be s3://existing-bucket/dedicated-prefix")
	}
	if !regexp.MustCompile(`^[0-9]{12}$`).MatchString(c.Account) || c.Region == "" {
		return errors.New("explicit AWS account and region required")
	}
	b, _ = json.MarshalIndent(c, "", "  ")
	if e = atomicWrite(path, b); e != nil {
		return e
	}
	fmt.Printf("Target account=%s region=%s environment=%s stack=sworn-ink/%s backend=%s/%s\n", c.Account, c.Region, c.Environment, c.Environment, c.Backend, c.Environment)
	r := commandRunner{root}
	if e = checkVersions(r, *action == "github-plan" || *action == "github-setup"); e != nil {
		return e
	}
	if *action == "build" {
		return build(root, c.Account+"/"+c.Region+"/"+c.Environment, r, *force)
	}
	if *action == "boundary-plan" || *action == "boundary-setup" {
		return boundarySetup(c, r, *action == "boundary-setup", *approve)
	}
	if *action == "oidc-plan" || *action == "oidc-setup" {
		return oidcSetup(c, r, *action == "oidc-setup", *approve)
	}
	if *action == "github-plan" || *action == "github-setup" {
		return github(c, r, *action == "github-setup", *approve)
	}
	awsEnv := []string{"AWS_REGION=" + c.Region}
	if interactive {
		if c.Profile == "" {
			return errors.New("interactive use requires an existing IAM Identity Center profile")
		}
		awsEnv = append(awsEnv, "AWS_PROFILE="+c.Profile)
		if _, e = r.Run("aws", []string{"sts", "get-caller-identity"}, awsEnv, nil); e != nil {
			cmd := exec.Command("aws", "sso", "login", "--profile", c.Profile)
			cmd.Stdin = os.Stdin
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if e = cmd.Run(); e != nil {
				return e
			}
		}
	}
	identity, e := r.Run("aws", []string{"sts", "get-caller-identity", "--output", "json"}, awsEnv, nil)
	if e != nil {
		return e
	}
	var id struct{ Account, Arn string }
	if e = json.Unmarshal(identity, &id); e != nil {
		return e
	}
	if id.Account != c.Account {
		return errors.New("AWS identity account differs from configured target")
	}
	fmt.Println("Verified AWS role:", id.Arn)
	if e = verifyState(c, r, awsEnv); e != nil {
		return e
	}
	pass := os.Getenv("PULUMI_CONFIG_PASSPHRASE")
	if pass == "" {
		if !interactive {
			return errors.New("PULUMI_CONFIG_PASSPHRASE is required")
		}
		vaultPath := filepath.Join(dir, "secrets.v1")
		vault, ve := os.ReadFile(vaultPath)
		unlock, e := hidden("Local vault unlock password")
		if e != nil {
			return e
		}
		if ve == nil {
			plain, e := openVault(vault, unlock)
			if e != nil {
				return e
			}
			pass = string(plain)
		} else if os.IsNotExist(ve) {
			again, e := hidden("Confirm vault password")
			if e != nil || again != unlock || len(unlock) < 12 {
				return errors.New("vault password mismatch or shorter than 12 characters")
			}
			pass, e = hidden("Pulumi passphrase (existing stack: preserve its original)")
			if e != nil {
				return e
			}
			again, e = hidden("Confirm Pulumi passphrase")
			if e != nil || again != pass || pass == "" {
				return errors.New("Pulumi passphrase mismatch")
			}
			sealed, e := seal([]byte(pass), unlock)
			if e != nil {
				return e
			}
			if e = atomicWrite(vaultPath, sealed); e != nil {
				return e
			}
		} else {
			return ve
		}
	}
	pEnv := append(awsEnv, "PULUMI_CONFIG_PASSPHRASE="+pass)
	infraRunner := commandRunner{filepath.Join(root, "infra")}
	pulumi := func(args ...string) ([]byte, error) { return infraRunner.Run("pulumi", args, pEnv, nil) }
	if _, e = pulumi("version"); e != nil {
		return e
	}
	if _, e = pulumi("login", c.Backend+"/"+c.Environment); e != nil {
		return e
	}
	yaml := filepath.Join(root, "infra", "Pulumi."+c.Environment+".yaml")
	remote := c.Backend + "/" + c.Environment + "/config/Pulumi." + c.Environment + ".yaml"
	restored, e := restoreConfig(r, awsEnv, yaml, remote, *action == "setup" && *approve)
	if e != nil {
		return e
	}
	if _, e = pulumi("stack", "select", c.Environment); e != nil {
		if *action != "setup" {
			return e
		}
		if !*approve {
			return errors.New("new stack requires setup --approve after checking no existing infrastructure belongs to this identity")
		}
		if _, e = pulumi("stack", "init", c.Environment, "--secrets-provider", "passphrase"); e != nil {
			return e
		}
	} else if !restored {
		return errors.New("existing stack lacks authoritative encrypted config; recover it before continuing")
	}
	if *action != "setup" && *action != "reconfigure" {
		if e = validateTarget(c, infraRunner, pEnv); e != nil {
			return e
		}
	}
	if *action == "status" || *action == "recovery" {
		out, e := pulumi("stack", "output", "--json")
		fmt.Print(string(out))
		return e
	}
	if *action == "setup" || *action == "reconfigure" {
		// Replace only this provider safety list, preserving all other configuration and secrets.
		if _, e = pulumi("config", "rm", "aws:allowedAccountIds"); e != nil {
			return e
		}
		if _, e = infraRunner.Run("pulumi", []string{"config", "set", "--path", "aws:allowedAccountIds[0]"}, pEnv, strings.NewReader(c.Account+"\n")); e != nil {
			return e
		}
		for _, v := range []struct{ Key, Env string }{{"aws:region", "AWS_REGION"}, {"awsAccount", "DEPLOY_ACCOUNT"}, {"jwtIssuer", "JWT_ISSUER"}, {"jwtAudience", "JWT_AUDIENCE"}, {"jwtScope", "JWT_SCOPE"}, {"appPackage", "ALLOWED_APP_PACKAGE"}, {"appDigests", "ALLOWED_APP_DIGESTS"}, {"googleRootsPEM", "GOOGLE_ROOTS_PEM"}} {
			value := os.Getenv(v.Env)
			if v.Key == "awsAccount" {
				value = c.Account
			}
			if v.Key == "aws:region" {
				value = c.Region
			}
			if value == "" {
				return fmt.Errorf("setup requires %s; saved Pulumi settings are never implicitly replaced", v.Env)
			}
			if _, e = infraRunner.Run("pulumi", []string{"config", "set", v.Key}, pEnv, strings.NewReader(value+"\n")); e != nil {
				return e
			}
		}
		if e = validateTarget(c, infraRunner, pEnv); e != nil {
			return e
		}
		_, e = r.Run("aws", []string{"s3", "cp", yaml, remote, "--sse", "AES256"}, awsEnv, nil)
		return e
	}
	if *action != "preview" && *action != "deploy" {
		return errors.New("unknown action")
	}
	if e = build(root, c.Account+"/"+c.Region+"/"+c.Environment, r, *force); e != nil {
		return e
	}
	plan := filepath.Join(dir, "preview.plan")
	out, e := pulumi("preview", "--refresh", "--diff", "--save-plan", plan)
	fmt.Print(string(out))
	if e != nil {
		return e
	}
	defer os.Remove(plan)
	if *action == "preview" {
		return nil
	}
	if interactive {
		terminal, err := confirmationTerminal()
		if err != nil {
			return err
		}
		accepted := confirm(terminal, os.Stdout, 5*time.Second)
		terminal.Close()
		if !accepted {
			return errors.New("deployment cancelled")
		}
	} else if !*approve {
		return errors.New("noninteractive deploy requires --approve")
	}
	latest, e := r.Run("aws", []string{"sts", "get-caller-identity", "--output", "json"}, awsEnv, nil)
	if e != nil {
		return e
	}
	var finalIdentity struct{ Account, Arn string }
	if json.Unmarshal(latest, &finalIdentity) != nil || finalIdentity.Account != id.Account || finalIdentity.Arn != id.Arn {
		return errors.New("AWS identity changed after preview; cancelled")
	}
	if e = validateTarget(c, infraRunner, pEnv); e != nil {
		return e
	}
	out, e = pulumi("up", "--yes", "--plan", plan)
	fmt.Print(string(out))
	if e != nil {
		return e
	}
	_, e = r.Run("aws", []string{"s3", "cp", yaml, remote, "--sse", "AES256"}, awsEnv, nil)
	return e
}
func verifyState(c configData, r runner, env []string) error {
	bucket := strings.Split(strings.TrimPrefix(c.Backend, "s3://"), "/")[0]
	call := func(op string) ([]byte, error) {
		return r.Run("aws", []string{"s3api", op, "--bucket", bucket, "--expected-bucket-owner", c.Account, "--output", "json"}, env, nil)
	}
	if _, e := call("head-bucket"); e != nil {
		return e
	}
	v, e := call("get-bucket-versioning")
	if e != nil {
		return e
	}
	var version struct{ Status string }
	json.Unmarshal(v, &version)
	if version.Status != "Enabled" {
		return errors.New("state bucket versioning must be Enabled")
	}
	v, e = call("get-public-access-block")
	if e != nil {
		return e
	}
	var public struct {
		PublicAccessBlockConfiguration struct{ BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets bool }
	}
	json.Unmarshal(v, &public)
	p := public.PublicAccessBlockConfiguration
	if !p.BlockPublicAcls || !p.IgnorePublicAcls || !p.BlockPublicPolicy || !p.RestrictPublicBuckets {
		return errors.New("state bucket must block all public access")
	}
	v, e = call("get-bucket-encryption")
	if e != nil {
		return e
	}
	if !bytes.Contains(v, []byte("SSEAlgorithm")) {
		return errors.New("state bucket encryption absent")
	}
	v, e = call("get-bucket-location")
	if e != nil {
		return e
	}
	var location struct{ LocationConstraint string }
	json.Unmarshal(v, &location)
	if location.LocationConstraint == "" {
		location.LocationConstraint = "us-east-1"
	}
	if location.LocationConstraint != c.Region {
		return errors.New("state bucket region differs from configured region")
	}
	return nil
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
