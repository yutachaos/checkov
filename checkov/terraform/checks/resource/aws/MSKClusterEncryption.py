from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


class MSKClusterEncryption(BaseResourceCheck):
    def __init__(self):
        name = "Ensure MSK Cluster encryption in rest and transit is enabled"
        id = "CKV_AWS_81"
        supported_resources = ['aws_msk_cluster']
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        self.evaluated_keys = []
        if 'encryption_info' in conf.keys():
            encryption = conf['encryption_info'][0]
            if 'encryption_at_rest_kms_key_arn' in encryption:
                if 'encryption_in_transit' in encryption:
                    self.evaluated_keys.append('encryption_info/[0]/encryption_in_transit')
                    transit = encryption['encryption_in_transit'][0]
                    if 'client_broker' in transit:
                        self.evaluated_keys.append('encryption_info/[0]/encryption_in_transit/[0]/client_broker')
                    if 'in_cluster' in transit:
                        self.evaluated_keys.append('encryption_info/[0]/encryption_in_transit/[0]/in_cluster')
                    if transit.get('client_broker')[0] != 'TLS' or transit.get('in_cluster')[0] is False:
                        return CheckResult.FAILED
                self.evaluated_keys.append('encryption_info/[0]/encryption_at_rest_kms_key_arn')
                return CheckResult.PASSED
        return CheckResult.FAILED


check = MSKClusterEncryption()
