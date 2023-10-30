resource "aws_config_configuration_aggregator" "account" {
  name = "configaggregator"

  account_aggregation_source {
    account_ids = ["272858488437"]
    regions     = ["us-east-1"]
  }
}