# Deliberately weak training sample for static IaC checks. Do not deploy it.
resource "aws_security_group_rule" "demo_ingress" {
  type        = "ingress"
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_iam_policy_document" "demo_policy" {
  statement {
    actions = ["*"]
  }
}

resource "aws_storage_bucket" "demo" {
  encrypted = false
}
