# Reviewed 2026-09-09: configuration addresses remain symbolic in plan/apply.
# https://developer.hashicorp.com/terraform/cli/commands/plan
# https://developer.hashicorp.com/terraform/cli/commands/apply
# https://opentofu.org/docs/cli/commands/plan/
# https://opentofu.org/docs/cli/commands/apply/
provider "aws" {
  region = var.region
}
data "external" "lookup" {
  program = var.program
}
module "child" {
  source = "./child"
}
resource "aws_instance" "web" {
  count = var.count
  ami = data.external.lookup.result.ami
}
