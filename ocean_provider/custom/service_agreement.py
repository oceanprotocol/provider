from ocean_utils.agreements.service_agreement import ServiceAgreement


class CustomServiceAgreement(ServiceAgreement):
    def get_price(self):
        return self.main['cost']
