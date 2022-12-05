from setting import DETECTION_RULE_SET

if DETECTION_RULE_SET == "rule1":
    print("Use detection rule set 1")
    import registry.rule1.signature as signature
    import registry.rule1.application as application
else:
    print("Use detection rule set 2")
    import registry.rule2.signature as signature
    import registry.rule2.application as application
