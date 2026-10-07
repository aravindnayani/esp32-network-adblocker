import pathlib
import re
import unittest

from gen_ca_bundle import ROOTS

HEADER = pathlib.Path(__file__).resolve().parent.parent / 'src' / 'ca_bundle.h'


def bundle_bytes():
    text = HEADER.read_text(encoding='utf-8')
    body = text.split('{', 1)[1]
    return bytes(int(b, 16) for b in re.findall(r'0x([0-9a-f]{2})', body))


class CaBundleTests(unittest.TestCase):
    def test_committed_bundle_is_well_formed_and_sorted(self):
        data = bundle_bytes()
        count = int.from_bytes(data[:2], 'big')
        self.assertEqual(count, len(ROOTS))

        names, pos = [], 2
        for _ in range(count):
            name_len = int.from_bytes(data[pos:pos + 2], 'big')
            key_len = int.from_bytes(data[pos + 2:pos + 4], 'big')
            name = data[pos + 4:pos + 4 + name_len]
            key = data[pos + 4 + name_len:pos + 4 + name_len + key_len]
            self.assertEqual(name[0], 0x30)          # subject Name is a DER SEQUENCE
            self.assertEqual(key[0], 0x30)           # so is SubjectPublicKeyInfo
            names.append(name)
            pos += 4 + name_len + key_len

        self.assertEqual(pos, len(data))             # no trailing or missing bytes
        self.assertEqual(names, sorted(names))       # firmware binary-searches by subject
        self.assertEqual(len(set(names)), count)


if __name__ == '__main__':
    unittest.main()
