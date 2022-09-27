## Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved
##
### SPDX-License-Identifier: MIT-0

resource "aws_lambda_function" "lambda_clicklogger_ingest" {
  filename      = var.lambda_source_zip_path
  function_name = "${var.app_prefix}-${var.stage_name}-ingestion-lambda"
  role          = aws_iam_role.click_logger_lambda_role.arn
  handler       = "com.clicklogs.Handlers.ClickLoggerHandler::handleRequest"
  runtime       = "java8"
  memory_size   = 2048
  timeout       = 300

  source_code_hash = filebase64sha256(var.lambda_source_zip_path)
  depends_on       = [
    aws_iam_role.click_logger_lambda_role, aws_kinesis_firehose_delivery_stream.click_logger_firehose_delivery_stream
  ]

  environment {
    variables = {
      STREAM_NAME = aws_kinesis_firehose_delivery_stream.click_logger_firehose_delivery_stream.name
      REGION      = data.aws_region.current.name
    }
  }

  vpc_config {
    subnet_ids         = [aws_subnet.click_logger_emr_private_subnet1.id]
    security_group_ids = [aws_security_group.click_logger_emr_security_group.id]
  }
}

resource "aws_lambda_function" "lambda_clicklogger_emr_start_job" {
  description = "Lambda to accept request to submit a job to an EMR Serverless cluster."
  filename      = var.lambda_source_zip_path
  function_name = "${var.app_prefix}-${var.stage_name}-emr-start-job-lambda"
  role          = aws_iam_role.click_logger_emr_lambda_role.arn
  handler       = "com.clicklogs.Handlers.ClickLoggerEMRJobHandler::handleRequest"
  runtime       = "java8"
  memory_size   = 2048
  timeout       = 600

  source_code_hash = filebase64sha256(var.lambda_source_zip_path)
  depends_on       = [aws_iam_role.click_logger_emr_lambda_role]

  environment {
    variables = {
      APPLICATION_NAME   = "${var.app_prefix}-${var.stage_name}-emr-serverless-application"
      APPLICATION_ID     = aws_emrserverless_application.click_log_loggregator_emr_serverless.id
      EXECUTION_ROLE_ARN = aws_iam_role.click_logger_emr_serverless_role.arn
      ENTRY_POINT        = "s3://${aws_s3_bucket.click_log_loggregator_source_s3_bucket.id}/${var.loggregator_jar}"
      MAIN_CLASS         = "--class com.examples.clicklogger.Loggregator"
      OUTPUT_BUCKET      = aws_s3_bucket.click_log_loggregator_output_s3_bucket.id
      SOURCE_BUCKET      = aws_s3_bucket.click_logger_firehose_delivery_s3_bucket.id
      LOGS_OUTPUT_PATH   = "s3://${aws_s3_bucket.click_log_loggregator_emr_serverless_logs_s3_bucket.id}"
      REGION             = data.aws_region.current.name
      EMR_GET_SLEEP_TIME = 5000
    }
  }
####creating event triggers and rules
 #CreateUser event on the transfer familty
resource "aws_cloudwatch_event_rule" "create_user" {
  name           = "${var.project}-${var.sftp_specs.server_name}-sftp-create-user"
  description    = "CreateUser event for each new user created for the SFTP server ${aws_transfer_server.sftp.id}"
  event_bus_name = "default"
  #role_arn       = aws_iam_role.aws_events_service_role.arn

  event_pattern = <<EOF
{
  "source": ["aws.transfer"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["transfer.amazonaws.com"],
    "eventName": ["CreateUser"],
    "requestParameters": {
      "serverId": ["${aws_transfer_server.sftp.id}"]
    }
  }
}
EOF

  tags = merge(
    {
      Name = "${var.project}-${var.sftp_specs.server_name}-sftp-create-user"
    },
    var.tags
  )
}

#This is to test if events are flowing, this can be removed later
resource "aws_cloudwatch_log_group" "transfer_events" {
  name              = "/aws/events/transfer/${var.project}-${var.sftp_specs.server_name}"
  retention_in_days = 7
  kms_key_id        = local.logs_kms_key_id

  tags = merge(
    {
      Name = "${var.project}-sftp-events"
    },
    var.tags
  )
}

data "aws_cloudwatch_log_group" "transfer_events" {
  name = "/aws/events/transfer/${var.project}-${var.sftp_specs.server_name}"

  depends_on = [
    aws_cloudwatch_log_group.transfer_events
  ]
}

# This is required for Event to be logged to the CW logs by Event Bus
data "aws_iam_policy_document" "events_logs" {
  statement {
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:PutLogEventsBatch",
    ]
    resources = ["arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/events/transfer/*:*"]
    principals {
      identifiers = [
        "events.amazonaws.com",
        "delivery.logs.amazonaws.com"
      ]
      type = "Service"
    }
  }
}

resource "aws_cloudwatch_log_resource_policy" "events_logs" {
  policy_document = data.aws_iam_policy_document.events_logs.json
  policy_name     = "trust-events-to-log-${var.project}-${var.sftp_specs.server_name}"
}

#This is to test if events are flowing, this can be removed later
resource "aws_cloudwatch_event_target" "create_user_log" {
  event_bus_name = "default"
  rule           = aws_cloudwatch_event_rule.create_user.name
  target_id      = "create-user-log"

  arn = data.aws_cloudwatch_log_group.transfer_events.arn
  #role_arn = "do we need role for log"

  retry_policy {
    maximum_event_age_in_seconds = 120
    maximum_retry_attempts       = 3
  }

  # TODO dead letter queue
  # dead_letter_config {
  #   arn = ""
  # }
}

resource "aws_cloudwatch_event_target" "create_user_lambda" {
  event_bus_name = "default"
  rule           = aws_cloudwatch_event_rule.create_user.name
  target_id      = "create_user_lambda"

  arn = aws_lambda_function.sftp_lambda.arn

  retry_policy {
    maximum_event_age_in_seconds = 120
    maximum_retry_attempts       = 3
  }

  # TODO dead letter queue
  # dead_letter_config {
  #   arn = ""
  # }
}
  
  vpc_config {
    subnet_ids         = [aws_subnet.click_logger_emr_private_subnet1.id]
    security_group_ids = [aws_security_group.click_logger_emr_security_group.id]
  }
}

output "lambda-clicklogger-ingest" {
  value = aws_lambda_function.lambda_clicklogger_ingest
}

output "lambda-clicklogger-emr-job" {
  value = aws_lambda_function.lambda_clicklogger_emr_start_job
}
