import sys,os
sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import server

IDOC="EDIDC|ORDERS|client\nE1EDK01|seg1\nE1EDP01|seg2"
def test_parse():
    assert server.parse_idoc(IDOC).message_type=="ORDERS"
def test_govern():
    assert any("SOX" in f for f in server.govern_sap("EDIDC|DEBMAS\nE1|x").frameworks)
