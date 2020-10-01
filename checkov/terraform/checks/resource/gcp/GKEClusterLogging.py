from checkov.terraform.checks.resource.base_resource_negative_value_check import BaseResourceNegativeValueCheck
from checkov.common.models.enums import CheckCategories


class GKEClusterLogging(BaseResourceNegativeValueCheck):
    def __init__(self):
        name = "Ensure Stackdriver Logging is set to Enabled on Kubernetes Engine Clusters"
        id = "CKV_GCP_1"
        supported_resources = ['google_container_cluster']
        categories = [CheckCategories.KUBERNETES]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def get_inspected_key(self):
        """
        Looks for public accessibility:
            https://www.terraform.io/docs/providers/aws/r/mq_broker.html#publicly_accessible
            https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html
        :param conf: aws_launch_configuration configuration
        :return: <CheckResult>
        """
        return 'logging_service'

    def get_forbidden_values(self):
        return ['none']


check = GKEClusterLogging()
