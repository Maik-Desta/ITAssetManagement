"""Status-distribution specs for the summary bars on list pages: (key, label, tone)."""

ASSET_STATUS = [("ACTIVE", "Installed – active", "good"), ("FAULTY", "Installed – faulty", "critical"),
                ("IN_STOCK", "In stock", "info"), ("IN_TRANSIT", "In transit", "transit"),
                ("UNDER_REPAIR", "Under repair", "serious"), ("MISSING", "Missing", "missing"),
                ("RETIRED", "Retired", "neutral")]
AUDIT_STATUS = [("COMPLETED", "Completed", "good"), ("IN_PROGRESS", "In progress", "transit"),
                ("SCHEDULED", "Scheduled", "info")]
REQUEST_STATUS = [("PENDING_APPROVAL", "Awaiting approval", "transit"), ("APPROVED", "Approved", "info"),
                  ("ORDERED", "Ordered", "store"), ("RECEIVED", "Received", "good"), ("REJECTED", "Rejected", "neutral")]
CHANGE_STATUS = [("PENDING_APPROVAL", "Awaiting approval", "transit"), ("APPROVED", "Approved", "info"),
                 ("IN_PROGRESS", "In progress", "store"), ("COMPLETED", "Completed", "good"),
                 ("REJECTED", "Rejected", "critical"), ("CANCELLED", "Cancelled", "neutral")]
SHIPMENT_STATUS = [("PACKED", "Packed", "info"), ("IN_TRANSIT", "In transit", "transit"),
                   ("DELIVERED", "Delivered", "good"), ("VARIANCE", "Variance", "critical"),
                   ("CANCELLED", "Cancelled", "neutral")]
BRANCH_STATE = [("online", "Online", "good"), ("degraded", "Degraded", "serious"), ("offline", "Offline", "critical"),
                ("not_monitored", "Not monitored", "neutral")]
EXCEPTION_TONES = {"UNAPPROVED_DEVICE": "critical", "MISSING_DEVICE": "missing", "ROGUE_DEVICE": "serious",
                   "SHIPMENT_VARIANCE": "critical", "RFID_MISMATCH": "transit", "IDENTITY_MISMATCH": "serious",
                   "LOCATION_MISMATCH": "transit", "GOODS_RECEIPT_VARIANCE": "transit", "CUSTODIAN_LEFT": "info"}
