#
# AWS Config Logs Bucket
#

module "config_logs" {
  source  = "trussworks/logs/aws"
  version = "~> 10"

  s3_bucket_name     = var.config_logs_bucket
  allow_config       = true
  config_logs_prefix = "config"
  force_destroy      = true
}

