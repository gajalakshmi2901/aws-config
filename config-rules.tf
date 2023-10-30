locals {
  aws_config_iam_password_policy = templatefile("${path.module}/config-policies/iam-password-policy.tpl",
    {
      password_require_uppercase = var.password_require_uppercase ? "true" : "false"
      password_require_lowercase = var.password_require_lowercase ? "true" : "false"
      password_require_symbols   = var.password_require_symbols ? "true" : "false"
      password_require_numbers   = var.password_require_numbers ? "true" : "false"
      password_min_length        = var.password_min_length
      password_reuse_prevention  = var.password_reuse_prevention
      password_max_age           = var.password_max_age
    }
  )

  aws_config_acm_certificate_expiration = templatefile("${path.module}/config-policies/acm-certificate-expiration.tpl",
    {
      acm_days_to_expiration = var.acm_days_to_expiration
    }
  ) 

  aws_config_ami_approved_tag = templatefile("${path.module}/config-policies/ami-approved-tag.tpl",
    {
      ami_required_tag_key_value = var.ami_required_tag_key_value
    }
  )  

  aws_config_cloudwatch_log_group_retention_period = templatefile("${path.module}/config-policies/cloudwatch-log-retention.tpl",
    {
      cw_loggroup_retention_period = var.cw_loggroup_retention_period
    }
  ) 

  aws_config_dynamodb_arn_encryption_list = templatefile("${path.module}/config-policies/dynamodb_arn_encryption_list.tpl",
    {
      dynamodb_arn_encryption_list = var.dynamodb_arn_encryption_list
    }
  )

  aws_config_access_key_max_age = templatefile("${path.module}/config-policies/access-keys-rotated.tpl",
    {
      access_key_max_age = var.access_key_max_age
    }
  )

  aws_config_logs_delivery_window = templatefile("${path.module}/config-policies/cloudtrail-cloudwatch-logs-enabled.tpl",
    {
      expected_delivery_window_age = var.expected_delivery_window_age
    }
  )

  aws_config_efs_encrypted_check = templatefile("${path.module}/config-policies/efs-encrypted-check.tpl",
    {
      kms_key_id = var.kms_key_id
    }
  )

  aws_config_elb_logging_s3_buckets = templatefile("${path.module}/config-policies/elb-logging-enabled.tpl",
    {
      elb_logging_s3_buckets = var.elb_logging_s3_buckets
    }
  )

  aws_config_exclude_permission_boundary = templatefile("${path.module}/config-policies/exclude-permission-boundary.tpl",
    {
      exclude_permission_boundary = var.exclude_permission_boundary
    }
  )

  aws_config_authorized_vpc_ids = templatefile("${path.module}/config-policies/internet-gateway-authorized-vpc-only.tpl",
    {
      authorized_vpc_ids = var.authorized_vpc_ids
    }
  )

  aws_config_ecs_no_environment_secrets = templatefile("${path.module}/config-policies/ecs-no-environment-secrets.tpl",
    {
      ecs_no_environment_secrets = var.ecs_no_environment_secrets
    }
  )

  aws_config_s3_bucket_public_access_prohibited_exclusion = templatefile("${path.module}/config-policies/s3_public_access_exclusion.tpl",
    {
      s3_bucket_public_access_prohibited_exclusion = var.s3_bucket_public_access_prohibited_exclusion
    }
  )

  aws_config_vpc_sg_authorized_ports = jsonencode({ for k, v in var.vpc_sg_authorized_ports : k => tostring(v) if v != null })
  aws_config_masterAccountID=templatefile("${path.module}/config-policies/masterAccountID.tpl",{
    masterAccountID=var.masterAccountID
  })
}


#
# AWS Config Rules
#

resource "aws_config_config_rule" "iam-password-policy" {
  count            = var.check_iam_password_policy ? 1 : 0
  name             = "iam-password-policy"
  description      = "Ensure the account password policy for IAM users meets the specified requirements"
  input_parameters = local.aws_config_iam_password_policy

  source {
    owner             = "AWS"
    source_identifier = "IAM_PASSWORD_POLICY"
  }

  maximum_execution_frequency = var.config_max_execution_frequency

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "cloudtrail-enabled" {
  count       = var.check_cloudtrail_enabled ? 1 : 0
  name        = "cloudtrail-enabled"
  description = "Ensure CloudTrail is enabled"

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }

  maximum_execution_frequency = var.config_max_execution_frequency

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "multi-region-cloud-trail-enabled" {
  count       = var.check_multi_region_cloud_trail ? 1 : 0
  name        = "multi-region-cloud-trail-enabled"
  description = "Checks that there is at least one multi-region AWS CloudTrail. The rule is NON_COMPLIANT if the trails do not match inputs parameters."

  source {
    owner             = "AWS"
    source_identifier = "MULTI_REGION_CLOUD_TRAIL_ENABLED"
  }

  maximum_execution_frequency = var.config_max_execution_frequency

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "cloud-trail-encryption-enabled" {
  count       = var.check_cloud_trail_encryption ? 1 : 0
  name        = "cloud-trail-encryption-enabled"
  description = "Checks whether AWS CloudTrail is configured to use the server side encryption (SSE) AWS Key Management Service (AWS KMS) customer master key (CMK) encryption. The rule is COMPLIANT if the KmsKeyId is defined."

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENCRYPTION_ENABLED"
  }

  maximum_execution_frequency = var.config_max_execution_frequency

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "cloud-trail-log-file-validation-enabled" {
  count       = var.check_cloud_trail_log_file_validation ? 1 : 0
  name        = "cloud-trail-log-file-validation-enabled"
  description = "Checks whether AWS CloudTrail creates a signed digest file with logs. AWS recommends that the file validation must be enabled on all trails. The rule is NON_COMPLIANT if the validation is not enabled."

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED"
  }

  maximum_execution_frequency = var.config_max_execution_frequency

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "instances-in-vpc" {
  count       = var.check_instances_in_vpc ? 1 : 0
  name        = "instances-in-vpc"
  description = "Ensure all EC2 instances run in a VPC"

  source {
    owner             = "AWS"
    source_identifier = "INSTANCES_IN_VPC"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "root-account-mfa-enabled" {
  count       = var.check_root_account_mfa_enabled ? 1 : 0
  name        = "root-account-mfa-enabled"
  description = "Ensure root AWS account has MFA enabled"

  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
  }

  maximum_execution_frequency = var.config_max_execution_frequency

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "acm-certificate-expiration-check" {
  count            = var.check_acm_certificate_expiration_check ? 1 : 0
  name             = "acm-certificate-expiration-check"
  description      = "Ensures ACM Certificates in your account are marked for expiration within the specified number of days"
  input_parameters = local.aws_config_acm_certificate_expiration

  source {
    owner             = "AWS"
    source_identifier = "ACM_CERTIFICATE_EXPIRATION_CHECK"
  }

  maximum_execution_frequency = var.config_max_execution_frequency

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "ec2-volume-inuse-check" {
  count       = var.check_ec2_volume_inuse_check ? 1 : 0
  name        = "ec2-volume-inuse-check"
  description = "Checks whether EBS volumes are attached to EC2 instances"

  source {
    owner             = "AWS"
    source_identifier = "EC2_VOLUME_INUSE_CHECK"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "ec2-imdsv2-check" {
  count       = var.check_ec2_imdsv2 ? 1 : 0
  name        = "ec2-imdsv2-check"
  description = "Checks if EC2 instances metadata is configured with IMDSv2 or not"

  source {
    owner             = "AWS"
    source_identifier = "EC2_IMDSV2_CHECK"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "ebs_snapshot_public_restorable" {
  count       = var.check_ebs_snapshot_public_restorable ? 1 : 0
  name        = "ebs-snapshot-public-restorable"
  description = "Checks whether Amazon Elastic Block Store snapshots are not publicly restorable"

  source {
    owner             = "AWS"
    source_identifier = "EBS_SNAPSHOT_PUBLIC_RESTORABLE_CHECK"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "iam-user-no-policies-check" {
  count       = var.check_iam_user_no_policies_check ? 1 : 0
  name        = "iam-user-no-policies-check"
  description = "Ensure that none of your IAM users have policies attached. IAM users must inherit permissions from IAM groups or roles."

  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_NO_POLICIES_CHECK"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "iam-group-has-users-check" {
  count       = var.check_iam_group_has_users_check ? 1 : 0
  name        = "iam-group-has-users-check"
  description = "Checks whether IAM groups have at least one IAM user."

  source {
    owner             = "AWS"
    source_identifier = "IAM_GROUP_HAS_USERS_CHECK"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "rds-storage-encrypted" {
  count       = var.check_rds_storage_encrypted ? 1 : 0
  name        = "rds-storage-encrypted"
  description = "Checks whether storage encryption is enabled for your RDS DB instances."

  source {
    owner             = "AWS"
    source_identifier = "RDS_STORAGE_ENCRYPTED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "rds-instance-public-access-check" {
  count       = var.check_rds_public_access ? 1 : 0
  name        = "rds-instance-public-access-check"
  description = "Checks whether the Amazon Relational Database Service (RDS) instances are not publicly accessible. The rule is non-compliant if the publiclyAccessible field is true in the instance configuration item."

  source {
    owner             = "AWS"
    source_identifier = "RDS_INSTANCE_PUBLIC_ACCESS_CHECK"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "rds-snapshots-public-prohibited" {
  count       = var.check_rds_snapshots_public_prohibited ? 1 : 0
  name        = "rds-snapshots-public-prohibited"
  description = "Checks if Amazon Relational Database Service (Amazon RDS) snapshots are public."

  source {
    owner             = "AWS"
    source_identifier = "RDS_SNAPSHOTS_PUBLIC_PROHIBITED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "guardduty-enabled-centralized" {
  count       = var.check_guard_duty ? 1 : 0
  name        = "guardduty-enabled-centralized"
  description = "Checks whether Amazon GuardDuty is enabled in your AWS account and region."

  source {
    owner             = "AWS"
    source_identifier = "GUARDDUTY_ENABLED_CENTRALIZED"
  }

  maximum_execution_frequency = var.config_max_execution_frequency

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "s3-bucket-public-write-prohibited" {
  count       = var.check_s3_bucket_public_write_prohibited ? 1 : 0
  name        = "s3-bucket-public-write-prohibited"
  description = "Checks that your S3 buckets do not allow public write access."

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "eip_attached" {
  count       = var.check_eip_attached ? 1 : 0
  name        = "eip-attached"
  description = "Checks whether all Elastic IP addresses that are allocated to a VPC are attached to EC2 instances or in-use elastic network interfaces (ENIs)."

  source {
    owner             = "AWS"
    source_identifier = "EIP_ATTACHED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "required-tags" {
  count       = var.check_required_tags ? 1 : 0
  name        = "required-tags"
  description = "Checks if resources are deployed with configured tags."

  scope {
    compliance_resource_types = var.required_tags_resource_types
  }

  input_parameters = jsonencode(var.required_tags)

  source {
    owner             = "AWS"
    source_identifier = "REQUIRED_TAGS"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "approved-amis-by-tag" {
  count            = var.check_approved_amis_by_tag ? 1 : 0
  name             = "approved-amis-by-tag"
  description      = "Checks whether running instances are using specified AMIs. Running instances that dont have at least one of the specified tags are noncompliant"
  input_parameters = local.aws_config_ami_approved_tag

  source {
    owner             = "AWS"
    source_identifier = "APPROVED_AMIS_BY_TAG"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "ec2-encrypted-volumes" {
  count       = var.check_ec2_encrypted_volumes ? 1 : 0
  name        = "ec2-volumes-must-be-encrypted"
  description = "Evaluates whether EBS volumes that are in an attached state are encrypted. Optionally, you can specify the ID of a KMS key to use to encrypt the volume."

  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "cloudwatch_log_group_encrypted" {
  count = var.check_cloudwatch_log_group_encrypted ? 1 : 0

  name        = "cloudwatch-log-group-encrypted"
  description = "Checks whether a log group in Amazon CloudWatch Logs is encrypted. The rule is NON_COMPLIANT if CloudWatch Logs has a log group without encryption enabled"

  source {
    owner             = "AWS"
    source_identifier = "CLOUDWATCH_LOG_GROUP_ENCRYPTED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "cw-loggroup-retention-period-check" {
  count = var.check_cw_loggroup_retention_period ? 1 : 0

  name        = "cloudwatch-log-group-retention"
  description = "Checks whether Amazon CloudWatch LogGroup retention period is set to specific number of days. The rule is NON_COMPLIANT if the retention period is not set or is less than the configured retention period."

  input_parameters = local.aws_config_cloudwatch_log_group_retention_period

  source {
    owner             = "AWS"
    source_identifier = "CW_LOGGROUP_RETENTION_PERIOD_CHECK"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "iam_root_access_key" {
  count = var.check_iam_root_access_key ? 1 : 0

  name        = "iam-root-access-key"
  description = "Checks whether the root user access key is available. The rule is COMPLIANT if the user access key does not exist"

  source {
    owner             = "AWS"
    source_identifier = "IAM_ROOT_ACCESS_KEY_CHECK"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "vpc_default_security_group_closed" {
  count = var.check_vpc_default_security_group_closed ? 1 : 0

  name        = "vpc-default-security-group-closed"
  description = "Checks that the default security group of any Amazon Virtual Private Cloud (VPC) does not allow inbound or outbound traffic"

  source {
    owner             = "AWS"
    source_identifier = "VPC_DEFAULT_SECURITY_GROUP_CLOSED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "s3_bucket_ssl_requests_only" {
  count = var.check_s3_bucket_ssl_requests_only ? 1 : 0

  name        = "s3-bucket-ssl-requests-only"
  description = "Checks whether S3 buckets have policies that require requests to use Secure Socket Layer (SSL)."

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SSL_REQUESTS_ONLY"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "mfa_enabled_for_iam_console_access" {
  count = var.check_mfa_enabled_for_iam_console_access ? 1 : 0

  name        = "mfa-enabled-for-iam-console-access"
  description = "Checks whether AWS Multi-Factor Authentication (MFA) is enabled for all AWS Identity and Access Management (IAM) users that use a console password. The rule is compliant if MFA is enabled."

  source {
    owner             = "AWS"
    source_identifier = "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "restricted_ssh" {
  count = var.check_restricted_ssh ? 1 : 0

  name        = "restricted-ssh"
  description = "Checks whether security groups that are in use disallow unrestricted incoming SSH traffic."

  source {
    owner             = "AWS"
    source_identifier = "INCOMING_SSH_DISABLED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "IAM_PASSWORD_POLICY" {
  count            = var.check_access_keys_rotated ? 1 : 0
  name             = "access-keys-rotated"
  description      = "Checks if the active access keys are rotated within the number of days specified in maxAccessKeyAge. The rule is NON_COMPLIANT if the access keys have not been rotated for more than maxAccessKeyAge number of days."
  input_parameters = local.aws_config_access_key_max_age

  source {
    owner             = "AWS"
    source_identifier = "ACCESS_KEYS_ROTATED"
  }

  maximum_execution_frequency = var.config_max_execution_frequency

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "cmk_backing_key_rotation_enabled" {
  count       = var.check_cmk_backing_key_rotated ? 1 : 0
  name        = "cmk-backing-key-rotation-enabled"
  description = "Checks if automatic key rotation is enabled for every AWS Key Management Service customer managed symmetric encryption key. The rule is NON_COMPLIANT if automatic key rotation is not enabled for an AWS KMS customer managed symmetric encryption key."

  source {
    owner             = "AWS"
    source_identifier = "CMK_BACKING_KEY_ROTATION_ENABLED"
  }

  maximum_execution_frequency = var.config_max_execution_frequency

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "cloud-trail-cloud-watch-logs-enabled" {
  count            = var.cloud_trail_cloud_watch_logs_enabled ? 1 : 0
  name             = "cloud-trail-cloud-watch-logs-enabled"
  description      = "Checks whether AWS CloudTrail trails are configured to send logs to Amazon CloudWatch logs. The trail is non-compliant if the CloudWatchLogsLogGroupArn property of the trail is empty."
  input_parameters = local.aws_config_logs_delivery_window

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_CLOUD_WATCH_LOGS_ENABLED"
  }

  maximum_execution_frequency = var.config_max_execution_frequency

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "dynamodb-table-encryption-enabled" {
  count       = var.check_dynamodb_table_encryption_enabled ? 1 : 0
  name        = "dynamodb-table-encryption-enabled"
  description = "Checks if the Amazon DynamoDB tables are encrypted and checks their status. The rule is COMPLIANT if the status is enabled or enabling."

  source {
    owner             = "AWS"
    source_identifier = "DYNAMODB_TABLE_ENCRYPTION_ENABLED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "dynamodb-table-encrypted-kms" {
  count            = var.check_dynamodb_table_encrypted_kms ? 1 : 0
  name             = "dynamodb-table-encrypted-kms"
  description      = "Checks if Amazon DynamoDB table is encrypted with AWS Key Management Service (KMS). NON_COMPLIANT if DynamoDB table is not encrypted with AWS KMS. Also NON_COMPLIANT if the encrypted AWS KMS key is not present in kmsKeyArns input parameter."
  input_parameters = local.aws_config_dynamodb_arn_encryption_list

  source {
    owner             = "AWS"
    source_identifier = "DYNAMODB_TABLE_ENCRYPTED_KMS"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "ecr-private-image-scanning-enabled" {
  count       = var.check_ecr_private_image_scanning_enabled ? 1 : 0
  name        = "ecr-private-image-scanning-enabled"
  description = "Checks if a private Amazon Elastic Container Registry (ECR) repository has image scanning enabled. The rule is NON_COMPLIANT if image scanning is not enabled for the private ECR repository."

  source {
    owner             = "AWS"
    source_identifier = "ECR_PRIVATE_IMAGE_SCANNING_ENABLED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "ecr-private-lifecycle-policy-configured" {
  count       = var.check_ecr_private_lifecycle_policy_configured ? 1 : 0
  name        = "ecr-private-lifecycle-policy-configured"
  description = "Checks if a private Amazon Elastic Container Registry (ECR) repository has at least one lifecycle policy configured. The rule is NON_COMPLIANT if no lifecycle policy is configured for the ECR private repository."

  source {
    owner             = "AWS"
    source_identifier = "ECR_PRIVATE_LIFECYCLE_POLICY_CONFIGURED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "ecs-awsvpc-networking-enabled" {
  count       = var.check_ecs_awsvpc_networking_enabled ? 1 : 0
  name        = "ecs-awsvpc-networking-enabled"
  description = "Checks if the networking mode for active ECSTaskDefinitions is set to ‘awsvpc’. This rule is NON_COMPLIANT if active ECSTaskDefinitions is not set to ‘awsvpc’."

  source {
    owner             = "AWS"
    source_identifier = "ECS_AWSVPC_NETWORKING_ENABLED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "ecs-containers-nonprivileged" {
  count       = var.check_ecs_containers_nonprivileged ? 1 : 0
  name        = "ecs-containers-nonprivileged"
  description = "Checks if the privileged parameter in the container definition of ECSTaskDefinitions is set to ‘true’. The rule is NON_COMPLIANT if the privileged parameter is ‘true’."

  source {
    owner             = "AWS"
    source_identifier = "ECS_CONTAINERS_NONPRIVILEGED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "ecs-containers-readonly-access" {
  count       = var.check_ecs_containers_readonly_access ? 1 : 0
  name        = "ecs-containers-readonly-access"
  description = "Checks if Amazon Elastic Container Service (Amazon ECS) Containers only have read-only access to its root filesystems. The rule NON_COMPLIANT if readonlyRootFilesystem parameter in the container definition of ECSTaskDefinitions is set to ‘false’."

  source {
    owner             = "AWS"
    source_identifier = "ECS_CONTAINERS_READONLY_ACCESS"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "ecs-no-environment-secrets" {
  count            = var.check_ecs_no_environment_secrets ? 1 : 0
  name             = "ecs-no-environment-secrets"
  description      = "Checks if secrets are passed as container environment variables. Rule is NON_COMPLIANT if 1 or more environment variable key matches a key listed in the 'secretKeys' parameter (excluding env variables from other locations such as Amazon S3)."
  input_parameters = local.aws_config_ecs_no_environment_secrets

  source {
    owner             = "AWS"
    source_identifier = "ECS_NO_ENVIRONMENT_SECRETS"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "efs-encrypted-check" {
  count            = var.enable_efs_encrypted_check ? 1 : 0
  name             = "efs-encrypted-check"
  description      = "Checks if Amazon Elastic File System is configured to encrypt file data using AWS Key Management Service. NON_COMPLIANT if encrypted key set to false on DescribeFileSystems or KmsKeyId key on DescribeFileSystems does not match the KmsKeyId parameter"
  input_parameters = local.aws_config_efs_encrypted_check

  source {
    owner             = "AWS"
    source_identifier = "EFS_ENCRYPTED_CHECK"
  }

  maximum_execution_frequency = var.config_max_execution_frequency

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "elb-deletion-protection-enabled" {
  count       = var.check_elb_deletion_protection_enabled ? 1 : 0
  name        = "elb-deletion-protection-enabled"
  description = "Checks if Elastic Load Balancing has deletion protection enabled. The rule is NON_COMPLIANT if deletion_protection.enabled is false."

  source {
    owner             = "AWS"
    source_identifier = "ELB_DELETION_PROTECTION_ENABLED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "elb-logging-enabled" {
  count            = var.check_elb_logging_enabled ? 1 : 0
  name             = "elb-logging-enabled"
  description      = "Checks if the Application Load Balancer and the Classic Load Balancer have logging enabled. The rule is NON_COMPLIANT if the access_logs.s3.enabled is false or access_logs.S3.bucket is not equal to the s3BucketName that you provided."
  input_parameters = local.aws_config_elb_logging_s3_buckets

  source {
    owner             = "AWS"
    source_identifier = "ELB_LOGGING_ENABLED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "iam-policy-no-statements-with-admin-access" {
  count       = var.check_iam_policy_no_statements_with_admin_access ? 1 : 0
  name        = "iam-policy-no-statements-with-admin-access"
  description = "Checks the IAM policies that you create for Allow statements that grant permissions to all actions on all resources. The rule is NON_COMPLIANT if any policy statement includes \"Effect\": \"Allow\" with \"Action\": \"*\" over \"Resource\": \"*\"."

  source {
    owner             = "AWS"
    source_identifier = "IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "iam-policy-no-statements-with-full-access" {
  count            = var.check_iam_policy_no_statements_with_full_access ? 1 : 0
  name             = "iam-policy-no-statements-with-full-access"
  description      = "Checks if AWS Identity and Access Management (IAM) policies grant permissions to all actions on individual AWS resources. The rule is NON_COMPLIANT if the managed IAM policy allows full access to at least 1 AWS service. "
  input_parameters = local.aws_config_exclude_permission_boundary

  source {
    owner             = "AWS"
    source_identifier = "IAM_POLICY_NO_STATEMENTS_WITH_FULL_ACCESS"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "nacl-no-unrestricted-ssh-rdp" {
  count       = var.check_nacl_no_unrestricted_ssh_rdp ? 1 : 0
  name        = "nacl-no-unrestricted-ssh-rdp"
  description = "Checks if default ports for SSH/RDP ingress traffic for network access control lists (NACLs) is unrestricted. The rule is NON_COMPLIANT if a NACL inbound entry allows a source TCP or UDP CIDR block for ports 22 or 3389."

  source {
    owner             = "AWS"
    source_identifier = "NACL_NO_UNRESTRICTED_SSH_RDP"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "internet-gateway-authorized-vpc-only" {
  count            = var.check_internet_gateway_authorized_vpc_only ? 1 : 0
  name             = "internet-gateway-authorized-vpc-only"
  description      = "Checks that Internet gateways (IGWs) are only attached to an authorized Amazon Virtual Private Cloud (VPCs). The rule is NON_COMPLIANT if IGWs are not attached to an authorized VPC."
  input_parameters = local.aws_config_authorized_vpc_ids

  source {
    owner             = "AWS"
    source_identifier = "INTERNET_GATEWAY_AUTHORIZED_VPC_ONLY"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "rds-snapshot-encrypted" {
  count       = var.check_rds_snapshot_encrypted ? 1 : 0
  name        = "rds-snapshot-encrypted"
  description = "Checks whether Amazon Relational Database Service (Amazon RDS) DB snapshots are encrypted. The rule is NON_COMPLIANT, if the Amazon RDS DB snapshots are not encrypted. "

  source {
    owner             = "AWS"
    source_identifier = "RDS_SNAPSHOT_ENCRYPTED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "rds-cluster-deletion-protection-enabled" {
  count       = var.check_rds_cluster_deletion_protection_enabled ? 1 : 0
  name        = "rds-cluster-deletion-protection-enabled"
  description = "Checks if an Amazon Relational Database Service (Amazon RDS) cluster has deletion protection enabled. The rule is NON_COMPLIANT if an Amazon RDS cluster does not have deletion protection enabled."

  source {
    owner             = "AWS"
    source_identifier = "RDS_CLUSTER_DELETION_PROTECTION_ENABLED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "db-instance-backup-enabled" {
  count       = var.check_db_instance_backup_enabled ? 1 : 0
  name        = "db-instance-backup-enabled"
  description = "Checks if RDS DB instances have backups enabled. Optionally, the rule checks the backup retention period and the backup window."

  source {
    owner             = "AWS"
    source_identifier = "DB_INSTANCE_BACKUP_ENABLED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "s3-bucket-level-public-access-prohibited" {
  count            = var.check_s3_bucket_level_public_access_prohibited ? 1 : 0
  name             = "s3-bucket-level-public-access-prohibited"
  description      = "Checks if Amazon Simple Storage Service (Amazon S3) buckets are publicly accessible. This rule is NON_COMPLIANT if an Amazon S3 bucket is not listed in the excludedPublicBuckets parameter and bucket level settings are public. "
  input_parameters = local.aws_config_s3_bucket_public_access_prohibited_exclusion

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "s3-bucket-acl-prohibited" {
  count       = var.check_s3_bucket_acl_prohibited ? 1 : 0
  name        = "s3-bucket-acl-prohibited"
  description = "Checks if Amazon Simple Storage Service (Amazon S3) Buckets allow user permissions through access control lists (ACLs). The rule is NON_COMPLIANT if ACLs are configured for user access in Amazon S3 Buckets."

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_ACL_PROHIBITED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "s3-bucket-server-side-encryption-enabled" {
  count       = var.check_s3_bucket_server_side_encryption_enabled ? 1 : 0
  name        = "s3-bucket-server-side-encryption-enabled"
  description = "Checks if S3 bucket either has the S3 default encryption enabled or that S3 policy explicitly denies put-object requests without SSE that uses AES-256 or AWS KMS. The rule is NON_COMPLIANT if your Amazon S3 bucket is not encrypted by default."

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "vpc-sg-open-only-to-authorized-ports" {
  count            = var.check_vpc_sg_open_only_to_authorized_ports ? 1 : 0
  name             = "vpc-sg-open-only-to-authorized-ports"
  description      = "Checks if security groups with inbound 0.0.0.0/0 have TCP or UDP ports accessible. NON_COMPLIANT if security group with inbound 0.0.0.0/0 has a port accessible which is not specified in rule parameters.(both Terraform inputs required if enabled)"
  input_parameters = local.aws_config_vpc_sg_authorized_ports

  source {
    owner             = "AWS"
    source_identifier = "VPC_SG_OPEN_ONLY_TO_AUTHORIZED_PORTS"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "ebs-optimized-instance" {
  count       = var.check_ebs_optimized_instance ? 1 : 0
  name        = "ebs-optimized-instance"
  description = "Checks if EBS optimization is enabled for your EC2 instances that can be EBS-optimized."

  source {
    owner             = "AWS"
    source_identifier = "EBS_OPTIMIZED_INSTANCE"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "s3-bucket-public-read-prohibited" {
  count       = var.check_s3_bucket_public_read_prohibited ? 1 : 0
  name        = "s3-bucket-public-read-prohibited"
  description = "Checks that your S3 buckets do not allow public read access."

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "restricted-common-ports" {
  count       = var.check_restricted_common_ports ? 1 : 0
  name        = "restricted-common-ports"
  description = "Checks if the security groups in use do not allow unrestricted incoming TCP traffic to the specified ports."

  source {
    owner             = "AWS"
    source_identifier = "RESTRICTED_INCOMING_TRAFFIC"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}
resource "aws_config_config_rule" "account_part_of_organization" {
  count       = var.check_account_part_of_organization ? 1 : 0
  name        = "account_part_of_organization"
  description = "Checks that your account is part of organization."
  input_parameters = local.masterAccountID
  source {
    owner             = "AWS"
    source_identifier = "ACCOUNT_PART_OF_ORGANIZATIONS"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}
resource "aws_config_config_rule" "alb_http_drop_invalid_header_enabled" {
  count       = var.check_alb_http_drop_invalid_header_enabled ? 1 : 0
  name        = "alb_http_drop_invalid_header_enabled"
  description = " Checks if rule evaluates Application Load Balancers (ALBs) to ensure they are configured to drop http headers. The rule is NON_COMPLIANT if the value of routing.http.drop_invalid_header_fields.enabled is set to false."

  source {
    owner             = "AWS"
    source_identifier = "ALB_HTTP_DROP_INVALID_HEADER_ENABLED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}
resource "aws_config_config_rule" "alb_http_to_https_redirection_check" {
  count       = var.check_alb_http_to_https_redirection_check ? 1 : 0
  name        = "alb_http_to_https_redirection_check"
  description = "Checks whether HTTP to HTTPS redirection is configured on all HTTP listeners of Application Load Balancer. The rule is NON_COMPLIANT if one or more HTTP listeners of Application Load Balancer do not have HTTP to HTTPS redirection configured."
  source {
    owner             = "AWS"
    source_identifier = "ALB_HTTP_TO_HTTPS_REDIRECTION_CHECK"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}
resource "aws_config_config_rule" "api_gw_execution_logging_enabled" {
  count       = var.check_api_gw_execution_logging_enabled? 1 : 0
  name        = "api_gw_execution_logging_enabled"
  description = "Checks that all methods in Amazon API Gateway stage has logging enabled. The rule is NON_COMPLIANT if logging is not enabled. The rule is NON_COMPLIANT if loggingLevel is neither ERROR nor INFO."

  source {
    owner             = "AWS"
    source_identifier = "API_GW_EXECUTION_LOGGING_ENABLED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}
resource "aws_config_config_rule" "api_gw_cache_enabled_and_encrypted" {
  count       = var.check_api_gw_cache_enabled_and_encrypted ? 1 : 0
  name        = "api_gw_cache_enabled_and_encrypted"
  description = "Checks that all methods in Amazon API Gateway stages have caching enabled and encrypted. The rule is NON_COMPLIANT  if any method in an API Gateway stage is not configured for caching or the cache is not encrypted"

  source {
    owner             = "AWS"
    source_identifier = "API_GW_CACHE_ENABLED_AND_ENCRYPTED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}
resource "aws_config_config_rule" "autoscaling_group_healthcheck_required" {
  count       = var.check_autoscaling_group_healthcheck_required? 1 : 0
  name        = "autoscaling_group_healthcheck_required"
  description = "  Checks whether your Auto Scaling groups that are associated with a load balancer areusing Elastic Load Balancing  health checks."

  source {
    owner             = "AWS"
    source_identifier = "AUTOSCALING_GROUP_ELB_HEALTHCHECK_REQUIRED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}
resource "aws_config_config_rule" "cloudformation_stack_notification_check" {
  count       = var.cloudformation_stack_notification_check? 1 : 0
  name        = "cloudformation_stack_notification_check"
  description = "   Checks whether your CloudFormation stacks are sending event notifications to an SNS topic. Optionally checks whether  specified SNS topics are used."

  source {
    owner             = "AWS"
    source_identifier = "CLOUDFORMATION_STACK_NOTIFICATION_CHECK"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}
resource "aws_config_config_rule" "cloudfront_default_root_object_configured" {
  count       = var.check_cloudfront_default_root_object_configured? 1 : 0
  name        = "cloudfront_default_root_object_configured"
  description = "    Checks if an Amazon CloudFront distribution is configured to return a specific object that is the default root  object. The rule is NON_COMPLIANT if CloudFront distribution does not have a default root object configured."

  source {
    owner             = "AWS"
    source_identifier = "CLOUDFRONT_DEFAULT_ROOT_OBJECT_CONFIGURED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}
resource "aws_config_config_rule" "cloudfront_origin_access_identity_enabled" {
  count       = var.check_cloudfront_origin_access_identity_enabled? 1 : 0
  name        = "cloudfront_origin_access_identity_enabled"
  description = "Checks that Amazon CloudFront distribution with Amazon S3 Origin type has Origin Access Identity (OAI) configured.  This rule is NON_COMPLIANT if the CloudFront distribution is backed by Amazon S3 and any of Amazon S3 Origin type is  not OAI configured."
  source {
    owner             = "AWS"
    source_identifier = " CLOUDFRONT_ORIGIN_ACCESS_IDENTITY_ENABLED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "cloudfront_sni_enabled" {
  count       = var.check_cloudfront_sni_enabled? 1 : 0
  name        = "cloudfront_sni_enabled"
  description = "  Checks if Amazon CloudFront distributions are using a custom SSL certificate"
  source {
    owner             = "AWS"
    source_identifier = "CLOUDFRONT_SNI_ENABLED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}



resource "aws_config_config_rule" "cloudfront_viewer_policy_https" {
  count       = var.check_cloudfront_viewer_policy_https? 1 : 0
  name        = "cloudfront_viewer_policy_https"
  description = "     Checks whether your Amazon CloudFront distributions use HTTPS"
  source {
    owner             = "AWS"
    source_identifier = "CLOUDFRONT_VIEWER_POLICY_HTTPS"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}
resource "aws_config_config_rule" "cloudfront_origin_failover_enabled" {
  count       = var.check_cloudfront_origin_failover_enabled? 1 : 0
  name        = "cloudfront_origin_failover_enabled"
  description = "Checks whether an origin group is configured for the distribution of at least 2 origins in the origin group for  Amazon CloudFront.  This rule is NON_COMPLIANT if there are no origin groups for the distribution."
  source {
    owner             = "AWS"
    source_identifier = "CLOUDFRONT_ORIGIN_FAILOVER_ENABLED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}
resource "aws_config_config_rule" "codebuild_project_envvar_awscred_check" {
  count       = var.check_codebuild_project_envvar_awscred_check? 1 : 0
  name        = "codebuild_project_envvar_awscred_check"
  description = "     Checks whether the project contains environment variables AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY. The rule is  NON_COMPLIANT when the project environment variables contains plaintext credentials."
  source {
    owner             = "AWS"
    source_identifier = "CODEBUILD_PROJECT_ENVVAR_AWSCRED_CHECK"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}
resource "aws_config_config_rule" "dms_replication_not_public" {
  count       = var.check_dms_replication_not_public? 1 : 0
  name        = "dms_replication_not_public"
  description = "Checks whether AWS Database Migration Service replication instances are public. The rule is NON_COMPLIANT if  PubliclyAccessible field is true."
  source {
    owner             = "AWS"
    source_identifier = "DMS_REPLICATION_NOT_PUBLIC"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}
resource "aws_config_config_rule" "dynamodb_in_backup_plan" {
  count       = var.check_dynamodb_in_backup_plan? 1 : 0
  name        = "dynamodb_in_backup_plan"
  description = "     Checks whether Amazon DynamoDB table is present in AWS Backup plans. The rule is NON_COMPLIANT if DynamoDB tables  are not present in any AWS Backup plan."
  source {
    owner             = "AWS"
    source_identifier = "DYNAMODB_IN_BACKUP_PLAN"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}
resource "aws_config_config_rule" "ec2_ebs_encryption_by_default" {
  count       = var.check_ec2_ebs_encryption_by_default? 1 : 0
  name        = "ec2_ebs_encryption_by_default"
  description = "Check that Amazon Elastic Block Store (EBS) encryption is enabled by default. The rule is NON_COMPLIANT if the  encryption is not enabled."
  source {
    owner             = "AWS"
    source_identifier = "EC2_EBS_ENCRYPTION_BY_DEFAULT"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}
resource "aws_config_config_rule" "ec2_instance_detailed_monitoring_enabled" {
  count       = var.check_ec2_instance_detailed_monitoring_enabled? 1 : 0
  name        = "ec2_instance_detailed_monitoring_enabled"
  description = "     Checks whether detailed monitoring is enabled for EC2 instances. The rule is NON_COMPLIANT if detailed monitoring is  not enabled"
  source {
    owner             = "AWS"
    source_identifier = "EC2_INSTANCE_DETAILED_MONITORING_ENABLED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}
resource "aws_config_config_rule" "ec2_instance_managed_by_ssm" {
  count       = var.check_ec2_instance_managed_by_ssm? 1 : 0
  name        = "ec2_instance_managed_by_ssm"
  description = "        Checks whether the Amazon EC2 instances in your account are managed by AWS Systems Manager."
  source {
    owner             = "AWS"
    source_identifier = "EC2_INSTANCE_MANAGED_BY_SSM"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}
resource "aws_config_config_rule" "ec2_instance_no_public_ip" {
  count       = var.check_ec2_instance_no_public_ip? 1 : 0
  name        = "ec2_instance_no_public_ip"
  description = "         Checks whether Amazon Elastic Compute Cloud (Amazon EC2) instances have a public IP association. The rule is  NON_COMPLIANT if the publicIp field is present in the Amazon EC2 instance configuration item. This rule applies only   to IPv4."
  source {
    owner             = "AWS"
    source_identifier = "EC2_INSTANCE_NO_PUBLIC_IP"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}
resource "aws_config_config_rule" "eks_secrets_encrypted" {
  count       = var.check_eks_secrets_encrypted? 1 : 0
  name        = "eks_secrets_encrypted"
  description = "Checks whether Amazon Elastic Kubernetes Service clusters are configured to have Kubernetes secrets encrypted using  AWS Key Management Service (KMS) keys. "
  source {
    owner             = "AWS"
    source_identifier = "EKS_SECRETS_ENCRYPTED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}
resource "aws_config_config_rule" "ec2_stopped_instance" {
  count       = var.check_ec2_stopped_instance_enabled? 1 : 0
  name        = "ec2_stopped_instance"
  description = "     Checks whether detailed monitoring is enabled for EC2 instances. The rule is NON_COMPLIANT if detailed monitoring is  not enabled"
  source {
    owner             = "AWS"
    source_identifier = "EC2_STOPPED_INSTANCE"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}
resource "aws_config_config_rule" "eks_endpoint_no_public_access" {
  count       = var.check_eks_endpoint_no_public_access? 1 : 0
  name        = "eks_endpoint_no_public_access"
  description = "    Checks whether Amazon Elastic Kubernetes Service (Amazon EKS) endpoint is not publicly accessible. The rule is   NON_COMPLIANT if the endpoint is publicly accessible."
  source {
    owner             = "AWS"
    source_identifier = "EKS_ENDPOINT_NO_PUBLIC_ACCESS"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}
resource "aws_config_config_rule" "elasticache_redis_cluster_automatic_backup_check" {
  count       = var.check_elasticache_redis_cluster_automatic_backup_check? 1 : 0
  name        = "elasticache_redis_cluster_automatic_backup_check"
  description = " Check if the Amazon ElastiCache Redis clusters have automatic backup turned on. "
  source {
    owner             = "AWS"
    source_identifier = "ELASTICACHE_REDIS_CLUSTER_AUTOMATIC_BACKUP_CHECK"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}
resource "aws_config_config_rule" "elb_acm_certificate_required" {
  count       = var.check_elb_acm_certificate_required? 1 : 0
  name        = "elb_acm_certificate_required"
  description = "       Checks whether the Classic Load Balancers use SSL certificates provided by AWS Certificate Manager."
  source {
    owner             = "AWS"
    source_identifier = "ELB_ACM_CERTIFICATE_REQUIRED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}
resource "aws_config_config_rule" "emr_master_no_public_ip" {
  count       = var.check_emr_master_no_public_ip? 1 : 0
  name        = "emr_master_no_public_ip"
  description = "         Checks whether Amazon Elastic MapReduce (EMR) clusters' master nodes have public IPs. The rule is NON_COMPLIANT if  the master node has a public IP"
  source {
    owner             = "AWS"
    source_identifier = "EMR_MASTER_NO_PUBLIC_IP"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}
resource "aws_config_config_rule" "root_account_hardware_mfa_enabled" {
  count       = var.check_root_account_hardware_mfa_enabled? 1 : 0
  name        = "root_account_hardware_mfa_enabled"
  description = "       Checks whether your AWS account is enabled to use multi-factor authentication (MFA) hardware device to sign in with   root credentials. The rule is NON_COMPLIANT if any virtual MFA devices are permitted for signing in with root"
  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_HARDWARE_MFA_ENABLED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "iam_no_inline_policy_check" {
  count       = var.check_iam_no_inline_policy_check? 1 : 0
  name        = "iam_no_inline_policy_check"
  description = "       Checks that inline policy feature is not in use. The rule is NON_COMPLIANT if an AWS Identity and Access Management   (IAM) user, IAM role or IAM group has any inline policy."
  source {
    owner             = "AWS"
    source_identifier = "IAM_NO_INLINE_POLICY_CHECK"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}
resource "aws_config_config_rule" "iam_user_mfa_enabled" {
  count       = var.check_iam_user_mfa_enabled? 1 : 0
  name        = "iam_user_mfa_enabled"
  description = "Checks whether the AWS Identity and Access Management users have multi-factor authentication (MFA) enabled."
  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_MFA_ENABLED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "lambda_function_public_access_prohibited" {
  count       = var.check_lambda_function_public_access_prohibited? 1 : 0
  name        = "lambda_function_public_access_prohibited"
  description = "        Checks whether the AWS Lambda function policy attached to the Lambda resource prohibits public access. If the Lambda function policy allows public access it is NON_COMPLIANT"
  source {
    owner             = "AWS"
    source_identifier = "LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}
resource "aws_config_config_rule" "lambda_inside_vpc" {
  count       = var.check_lambda_inside_vpc? 1 : 0
  name        = "lambda_inside_vpc"
  description = "Checks whether an AWS Lambda function is in an Amazon Virtual Private Cloud. The rule is NON_COMPLIANT if the Lambda function is not in a VPC"
  source {
    owner             = "AWS"
    source_identifier = "LAMBDA_INSIDE_VPC"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}
resource "aws_config_config_rule" "rds_in_backup_plan" {
  count       = var.check_rds_in_backup_plan? 1 : 0
  name        = "rds_in_backup_plan"
  description = "        Checks whether Amazon RDS database is present in back plans of AWS Backup. The rule is NON_COMPLIANT if Amazon RDS   databases are not included in any AWS Backup plan."
  source {
    owner             = "AWS"
    source_identifier = "RDS_IN_BACKUP_PLAN"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}
resource "aws_config_config_rule" "rds_instance_deletion_protection_enabled" {
  count       = var.check_rds_instance_deletion_protection_enabled? 1 : 0
  name        = "rds_instance_deletion_protection_enabled"
  description = " Checks if an Amazon Relational Database Service (Amazon RDS) instance has deletion protection enabled. This rule is NON_COMPLIANT if an Amazon RDS instance does not have deletion protection enabled i.e deletionProtection is set to false."

  source {
    owner             = "AWS"
    source_identifier = "RDS_INSTANCE_DELETION_PROTECTION_ENABLED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}
resource "aws_config_config_rule" "rds_instance_iam_authentication_enabled" {
  count       = var.check_rds_instance_iam_authentication_enabled? 1 : 0
  name        = "rds_instance_iam_authentication_enabled"
  description = "Checks if an Amazon Relational Database Service (Amazon RDS) instance has AWS Identity and Access Management (IAM)   authentication enabled. "
  source {
    owner             = "AWS"
    source_identifier = "RDS_INSTANCE_IAM_AUTHENTICATION_ENABLED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}
resource "aws_config_config_rule" "rds_logging_enabled" {
  count       = var.check_rds_logging_enabled? 1 : 0
  name        = "rds_logging_enabled"
  description = "Checks that respective logs of Amazon Relational Database Service (Amazon RDS) are enabled. The rule is   NON_COMPLIANT if any log types are not enabled."
  source {
    owner             = "AWS"
    source_identifier = "RDS_LOGGING_ENABLED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}
resource "aws_config_config_rule" "rds_multi_az_support" {
  count       = var.check_rds_multi_az_support? 1 : 0
  name        = "rds_multi_az_support"
  description = "Checks whether high availability is enabled for your RDS DB instances."
  source {
    owner             = "AWS"
    source_identifier = "RDS_MULTI_AZ_SUPPORT"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}


resource "aws_config_config_rule" "redshift_backup_enabled" {
  count       = var.check_redshift_backup_enabled? 1 : 0
  name        = "redshift_backup_enabled"
  description = "Checks that Amazon Redshift automated snapshots are enabled for clusters. The rule is NON_COMPLIANT if the value for  automatedSnapshotRetentionPeriod is greater than MaxRetentionPeriod or less than MinRetentionPeriod or the value is 0."
  source {
    owner             = "AWS"
    source_identifier = "REDSHIFT_BACKUP_ENABLED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}
resource "aws_config_config_rule" "redshift_cluster_public_access_check" {
  count       = var.check_redshift_cluster_public_access_check? 1 : 0
  name        = "redshift_cluster_public_access_check"
  description = " Checks whether Amazon Redshift clusters are not publicly accessible. The rule is NON_COMPLIANT if the   publiclyAccessible field is true in the cluster configuration item"
  source {
    owner             = "AWS"
    source_identifier = "REDSHIFT_CLUSTER_PUBLIC_ACCESS_CHECK"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}
resource "aws_config_config_rule" "redshift_require_tls_ssl" {
  count       = var.check_redshift_require_tls_ssl? 1 : 0
  name        = "redshift_require_tls_ssl"
  description = "Checks whether Amazon Redshift clusters require TLS/SSL encryption to connect to SQL clients. The rule is  NON_COMPLIANT if any Amazon Redshift cluster has parameter require_SSL not set to true."
  source {
    owner             = "AWS"
    source_identifier = "REDSHIFT_REQUIRE_TLS_SSL"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "vpc_flow_logs_enabled" {
  count       = var.vpc_flow_logs_enabled? 1 : 0
  name        = "vpc_flow_logs_enabled"
  description = "Checks if Amazon Virtual Private Cloud (Amazon VPC) flow logs are found and enabled for all Amazon VPCs. The rule is NON_COMPLIANT if flow logs are not enabled for at least one Amazon VPC."
  source {
    owner             = "AWS"
    source_identifier = "VPC_FLOW_LOGS_ENABLED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}
resource "aws_config_config_rule" "wafv2_logging_enabled" {
  count       = var.check_wafv2_logging_enabled? 1 : 0
  name        = "wafv2-logging-enabled"
  description = "Checks if logging is enabled on AWS WAFv2 regional and global web access control lists (web ACLs). The rule is NON_COMPLIANT if the logging is enabled but the logging destination does not match the value of the parameter."
  source {
    owner             = "AWS"
    source_identifier = "WAFV2_LOGGING_ENABLED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}
resource "aws_config_config_rule" "s3_bucket_versioning_enabled" {
  count       = var.check_rds_multi_az_support? 1 : 0
  name        = "s3-bucket-versioning-enabled"
  description = "Checks if versioning is enabled for your S3 buckets. Optionally, the rule checks if MFA delete is enabled for your S3 buckets."
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_VERSIONING_ENABLED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}
resource "aws_config_config_rule" "s3_bucket_replication_enabled" {
  count       = var.check_s3_bucket_replication_enabled? 1 : 0
  name        = "s3_bucket_replication_enabled"
  description = "Checks if S3 buckets have replication rules enabled. The rule is NON_COMPLIANT if an S3 bucket does not have a replication rule or has a replication rule that is not enabled."
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_REPLICATION_ENABLED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}
resource "aws_config_config_rule" "s3_account_level_public_access_blocks" {
  count       = var.check_s3_account_level_public_access_blocks? 1 : 0
  name        = "s3_account_level_public_access_blocks"
  description = "Checks if the required public access block settings are configured from account level. The rule is only NON_COMPLIANT when the fields set below do not match the corresponding fields in the configuration item."
  source {
    owner             = "AWS"
    source_identifier = "S3_ACCOUNT_LEVEL_PUBLIC_ACCESS_BLOCKS"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "multi_region_cloud_trail_enabled" {
  count       = var.check_multi_region_cloud_trail_enabled? 1 : 0
  name        = "multi_region_cloud_trail_enabled"
  description = "Checks if there is at least one multi-region AWS CloudTrail. The rule is NON_COMPLIANT if the trails do not match input parameters"
  source {
    owner             = "AWS"
    source_identifier = "MULTI_REGION_CLOUD_TRAIL_ENABLED"
  }

  tags = var.tags

  depends_on = [aws_config_configuration_recorder.main]
}
