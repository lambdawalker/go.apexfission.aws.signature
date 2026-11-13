// Package artifacts lists independently buildable signature Lambda commands.
package artifacts

const Module = "github.com/lambdawalker/go.apexfission.aws.signature"

type Lambda struct{ Name, Package string }

func Lambdas() []Lambda { return []Lambda{{Name: "signature-api", Package: Module + "/cmd/api"}} }
