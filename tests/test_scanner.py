from monitor.scanner import Scan

S = Scan()


def test_reverse_ip():
    reversed_ip = S.reverse_ip('192.168.1.23')
    assert reversed_ip == '23.1.168.192'


def test_ven():
    vendor = S.get_ven('00:1b:63:84:45:e6')
    assert 'apple' in vendor.lower()


def test_gate():
    gateway = S.get_gate()

    assert gateway == '192.168.1.1'
