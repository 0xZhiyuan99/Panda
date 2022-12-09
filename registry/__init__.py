from setting import DETECTION_RULE_SET

if DETECTION_RULE_SET == "rule1":
    import registry.rule1.signature as signature
    import registry.rule1.application as application
else:
    import registry.rule2.signature as signature
    import registry.rule2.application as application
