from PLUGINS.Mock.SIRP.mock_case import *
from PLUGINS.SIRP.sirpapi import Case

if __name__ == "__main__":
    import os
    import django

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ASP.settings")
    django.setup()

    for case in [
        # case1_phishing,
        # case2_lateral_movement,
        # case3_dns_tunnel,
        # case4_brute_force,
        # case5_ransomware,
        # case6_unauthorized_access,
        # case7_data_exfil,
        # case8_email_campaign,
        # case9_priv_esc,
        # case10_cloud_misconfig,
        case11_brute_force,
        # case12_sql_injection,
        # case13_ransomware
    ]:
        Case.create(case)
