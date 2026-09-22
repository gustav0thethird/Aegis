# tflint configuration. Run from terraform/: `tflint --init && tflint`.

plugin "terraform" {
  enabled = true
  preset  = "recommended"
}

# Provider-aware rules: invalid instance classes, deprecated arguments,
# and similar mistakes that `terraform validate` cannot see.
plugin "aws" {
  enabled = true
  version = "0.49.0"
  source  = "github.com/terraform-linters/tflint-ruleset-aws"
}
