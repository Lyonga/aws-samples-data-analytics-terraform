resource "aws_transfer_server" "sftp" {
  endpoint_type          = "VPC"
  security_policy_name   = "TransferSecurityPolicy-2020-06"
  protocols              = ["SFTP"]
  domain                 = "EFS"
  identity_provider_type = "SERVICE_MANAGED"

  force_destroy = true

  endpoint_details {
    vpc_id             = data.aws_vpc.vpc.id
    subnet_ids         = data.aws_subnets.subnets.ids
    security_group_ids = [data.aws_security_group.sftp_sg.id]
    #Do we need EIP
    #address_allocation_ids = []
  }

  logging_role = data.aws_iam_role.transfer_logging.arn

  tags = merge(
    {
      Name = "${var.project}-sftp-server-${var.sftp_specs.server_name}"
    },
    var.tags
  )
}

#needed for output and R53
data "aws_vpc_endpoint" "sftp" {
  id = aws_transfer_server.sftp.endpoint_details[0].vpc_endpoint_id
}

resource "aws_transfer_user" "sftp_user" {
  for_each  = { for sftp_user in var.sftp_users : sftp_user.name => sftp_user }
  server_id = aws_transfer_server.sftp.id
  user_name = each.value.name
  role      = data.aws_iam_role.transfer_user.arn

  home_directory_type = "LOGICAL"
  home_directory_mappings {
    entry  = "/"
    target = "/${local.efs.efs_id}${local.efs_ap_root}/${aws_transfer_server.sftp.id}/home/${each.value.name}"
  }
  posix_profile {
    uid = each.value.uid
    gid = each.value.gid
  }

  tags = merge(
    {
      Name = each.value.name
    },
    var.tags
  )

  depends_on = [
    aws_cloudwatch_event_rule.create_user,
    aws_cloudwatch_event_target.create_user_log,
    aws_cloudwatch_event_target.create_user_lambda,
    aws_lambda_function.sftp_lambda
  ]
}

resource "aws_transfer_ssh_key" "sftp_user_key" {
  for_each  = { for sftp_user in var.sftp_users : sftp_user.name => sftp_user }
  server_id = aws_transfer_server.sftp.id
  user_name = aws_transfer_user.sftp_user[each.value.name].user_name
  body      = file(each.value.ssh_key_file)
}

# R53 entry for SFTP server
resource "aws_route53_record" "sftp_rec" {
  count = local.create_r53_record ? 1 : 0

  zone_id         = data.aws_route53_zone.pvt_zone[count.index].zone_id
  name            = "${var.sftp_specs.server_name}.${data.aws_route53_zone.pvt_zone[count.index].name}"
  allow_overwrite = true
  type            = "A"
  alias {
    name                   = data.aws_vpc_endpoint.sftp.dns_entry[0].dns_name
    zone_id                = data.aws_vpc_endpoint.sftp.dns_entry[0].hosted_zone_id
    evaluate_target_health = true
  }
}

resource "aws_cloudwatch_log_group" "transfer_logs" {
  name              = "/aws/transfer/${aws_transfer_server.sftp.id}"
  retention_in_days = 7
  kms_key_id        = local.logs_kms_key_id

  tags = merge(
    {
      Name = "${var.project}-${var.sftp_specs.server_name}-sftp-logs"
    },
    var.tags
  )
}

  ##creating roles and users
  data "aws_iam_policy_document" "transfer_assume_role" {
  count = local.create_sftp_logging_role ? 1 : 0

  statement {
    sid = "AllowAssumeRoleToTransferService"
    principals {
      type        = "Service"
      identifiers = ["transfer.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

data "aws_iam_policy_document" "transfer_logging" {
  count = local.create_sftp_logging_role ? 1 : 0

  statement {
    sid = "TransferLoggingAccessPermissions"
    actions = [
      "logs:CreateLogStream",
      "logs:DescribeLogStreams",
      "logs:CreateLogGroup",
      "logs:PutLogEvents"
    ]
    resources = [
      "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/transfer/*:*"
    ]
  }
}

resource "aws_iam_policy" "transfer_logging" {
  count = local.create_sftp_logging_role ? 1 : 0

  name        = "${local.sftp_logging_role_name}-policy"
  description = "Policy that allows the SFTP server to log to CloudWatch"
  policy      = data.aws_iam_policy_document.transfer_logging[count.index].json
  #tags = var.tags
}

resource "aws_iam_role" "transfer_logging" {
  count = local.create_sftp_logging_role ? 1 : 0

  name               = local.sftp_logging_role_name
  description        = "This role is used by transfer service to log to CloudWatch"
  assume_role_policy = data.aws_iam_policy_document.transfer_assume_role[count.index].json
  #tags = var.tags
}

resource "aws_iam_role_policy_attachment" "transfer_logging" {
  count = local.create_sftp_logging_role ? 1 : 0

  role       = aws_iam_role.transfer_logging[count.index].name
  policy_arn = aws_iam_policy.transfer_logging[count.index].arn
}

data "aws_iam_role" "transfer_logging" {
  name = local.sftp_logging_role_name

  depends_on = [
    aws_iam_role.transfer_logging
  ]
}

data "aws_iam_policy_document" "transfer_user" {
  count = local.create_sftp_user_role ? 1 : 0

  statement {
    sid = "TransferUserReadWritePermissions"
    actions = [
      "elasticfilesystem:ClientMount",
      "elasticfilesystem:ClientWrite"
    ]
    resources = [
      "arn:aws:elasticfilesystem:*:*:file-system/*",
    ]
  }
}

resource "aws_iam_policy" "transfer_user" {
  count = local.create_sftp_user_role ? 1 : 0

  name        = "${local.sftp_user_role_name}-policy"
  description = "Policy that allows read-write permission to EFS for the transfer service user"
  policy      = data.aws_iam_policy_document.transfer_user[count.index].json
  #tags = var.tags
}

resource "aws_iam_role" "transfer_user" {
  count = local.create_sftp_user_role ? 1 : 0

  name               = local.sftp_user_role_name
  description        = "This role can be assumed by SFTP user"
  assume_role_policy = data.aws_iam_policy_document.transfer_assume_role[count.index].json
  #tags = var.tags
}

resource "aws_iam_role_policy_attachment" "transfer_user" {
  count = local.create_sftp_user_role ? 1 : 0

  role       = aws_iam_role.transfer_user[count.index].name
  policy_arn = aws_iam_policy.transfer_user[count.index].arn
}

data "aws_iam_role" "transfer_user" {
  name = local.sftp_user_role_name

  depends_on = [
    aws_iam_role.transfer_user
  ]
}

data "aws_iam_policy_document" "lambda_assume_role" {
  count = local.create_sftp_lambda_role ? 1 : 0

  statement {
    sid = "AllowAssumeRoleToLambdaService"
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

data "aws_iam_policy_document" "sftp_lambda" {
  # checkov:skip=CKV_AWS_111: recommended for lambda
  count = local.create_sftp_lambda_role ? 1 : 0

  statement {
    actions = [
      "lambda:GetFunctionConfiguration"
    ]
    resources = [
      "*"
    ]
  }
  statement {
    actions = [
      "ec2:CreateNetworkInterface",
      "ec2:DeleteNetworkInterface",
      "ec2:DescribeNetworkInterfaces"
    ]
    resources = [
      "*"
    ]
  }
  statement {
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = [
      "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/*:*",
      "arn:aws:logs:*:*:log-group:/aws/lambda-insights:*"
    ]
  }
  statement {
    actions = [
      "logs:StartQuery",
      "logs:GetQueryResults"
    ]
    resources = [
      "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:*:*"
    ]
  }
  statement {
    actions = [
      "xray:PutTraceSegments",
      "xray:PutTelemetryRecords"
    ]
    resources = [
      "*"
    ]
  }
  statement {
    actions = [
      "SNS:Publish"
    ]
    resources = [
      "arn:aws:sns:${var.region}:${data.aws_caller_identity.current.account_id}:*"
    ]
  }
}

resource "aws_iam_policy" "sftp_lambda" {
  count = local.create_sftp_lambda_role ? 1 : 0

  name        = "${local.sftp_lambda_role_name}-policy"
  description = "Policy that allows Lambda Service access to CW and network"
  policy      = data.aws_iam_policy_document.sftp_lambda[count.index].json
  #tags = var.tags
}

resource "aws_iam_role" "sftp_lambda" {
  count = local.create_sftp_lambda_role ? 1 : 0

  name               = local.sftp_lambda_role_name
  description        = "This role is assumed by Lambda service for SFTP functions"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role[count.index].json
  #tags = var.tags
}

resource "aws_iam_role_policy_attachment" "sftp_lambda" {
  count = local.create_sftp_lambda_role ? 1 : 0

  role       = aws_iam_role.sftp_lambda[count.index].name
  policy_arn = aws_iam_policy.sftp_lambda[count.index].arn
}

data "aws_iam_role" "sftp_lambda" {
  name = local.sftp_lambda_role_name

  depends_on = [
    aws_iam_role.sftp_lambda
  ]
}
  
##SG
resource "aws_security_group" "sftp_sg" {
  # checkov:skip=CKV2_AWS_5: SG is attached in the resource module
  # checkov:skip=CKV_AWS_23: N/A
  count = local.create_sftp_sg ? 1 : 0

  name        = "${var.project}-${var.sftp_specs.server_name}-sftp-sg"
  description = "Allow inbound traffic from source to SFTP server"
  vpc_id      = data.aws_vpc.vpc.id

  tags = merge(
    {
      Name = "${var.project}-${var.sftp_specs.server_name}-sftp-sg"
    },
    var.tags
  )
}

#tfsec:ignore:aws-vpc-no-public-ingress-sgr
resource "aws_security_group_rule" "ingress_sftp_sg" {
  count = local.create_sftp_sg ? 1 : 0

  description       = "Allow inbound traffic from source to SFTP server"
  type              = "ingress"
  from_port         = var.sftp_specs.security_group.sftp_port
  to_port           = var.sftp_specs.security_group.sftp_port
  protocol          = "tcp"
  cidr_blocks       = var.sftp_specs.security_group.source_cidrs
  security_group_id = aws_security_group.sftp_sg[0].id
}

#tfsec:ignore:aws-vpc-no-public-egress-sgr
resource "aws_security_group_rule" "egress_sftp_sg" {
  count = local.create_sftp_sg ? 1 : 0

  description       = "Allow egress to all from SFTP Server"
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.sftp_sg[0].id
}

data "aws_security_group" "sftp_sg" {
  id   = local.create_sftp_sg ? aws_security_group.sftp_sg[0].id : null
  tags = local.create_sftp_sg ? null : var.sftp_specs.security_group.tags
}

resource "aws_security_group" "lambda_sg" {
  # checkov:skip=CKV2_AWS_5: SG is attached in the resource module
  # checkov:skip=CKV_AWS_23: N/A
  count = local.create_lambda_sg ? 1 : 0

  name        = "${local.sftp_lambda_name}-sg"
  description = "Allow outbound traffic from lambda to VPC"
  vpc_id      = data.aws_vpc.vpc.id

  tags = merge(
    {
      Name = "${local.sftp_lambda_name}-sg"
    },
    var.tags
  )
}

#tfsec:ignore:aws-vpc-no-public-ingress-sgr
resource "aws_security_group_rule" "ingress_lambda_sg" {
  count = local.create_lambda_sg ? 1 : 0

  description              = "Allow ingress from the same SG"
  type                     = "ingress"
  from_port                = 0
  to_port                  = 0
  protocol                 = "-1"
  source_security_group_id = aws_security_group.lambda_sg[0].id
  security_group_id        = aws_security_group.lambda_sg[0].id
}

#tfsec:ignore:aws-vpc-no-public-egress-sgr
resource "aws_security_group_rule" "egress_lambda_sg" {
  count = local.create_lambda_sg ? 1 : 0

  description       = "Allow egress to all from Lambda"
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.lambda_sg[0].id
}

data "aws_security_group" "lambda_sg" {
  id   = local.create_lambda_sg ? aws_security_group.lambda_sg[0].id : null
  tags = local.create_lambda_sg ? null : var.sftp_specs.lambda_specs.security_group_tags
}

data "aws_security_group" "sftp_efs" {
  id   = local.create_efs_sg ? module.transfer_efs[0].efs.sg_id : null
  tags = local.create_efs_sg ? null : var.sftp_specs.efs_specs.security_group_tags
}

resource "aws_security_group_rule" "allow_lambda_ingress_to_efs" {
  type                     = "ingress"
  from_port                = 2049
  to_port                  = 2049
  protocol                 = "tcp"
  description              = "Allow Lambda access to the EFS"
  security_group_id        = data.aws_security_group.sftp_efs.id
  source_security_group_id = data.aws_security_group.lambda_sg.id
}
 
