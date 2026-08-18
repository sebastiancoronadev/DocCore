import sys
import os
import math
import json
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', '熵数学分析器'))

from entropy_analyzer import 熵数学分析器

class Test熵计算(unittest.TestCase):
    def test_均匀分布(self):
        data = bytes(range(256)) * 100
        result = 熵数学分析器.完整分析_from_bytes(data)
        self.assertAlmostEqual(result["熵分析"]["香农熵"], 1.0, places=2)
    
    def test_全零数据(self):
        data = bytes([0] * 1000)
        result = 熵数学分析器.完整分析_from_bytes(data)
        self.assertEqual(result["熵分析"]["香农熵"], 0.0)
    
    def test_随机数据(self):
        import random
        random.seed(42)
        data = bytes(random.randint(0, 255) for _ in range(10000))
        result = 熵数学分析器.完整分析_from_bytes(data)
        self.assertGreater(result["熵分析"]["香农熵"], 0.95)

if __name__ == "__main__":
    unittest.main()
