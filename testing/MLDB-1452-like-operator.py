#
# MLDB-1452-like-operator
# 2016-03-16
# This file is part of MLDB. Copyright 2016 Datacratic. All rights reserved.
#

import unittest, json
mldb = mldb_wrapper.wrap(mldb) # noqa

class LikeTest(unittest.TestCase):

    def test_like_select(self):

        ds = mldb.create_dataset({ "id": "sample", "type": "sparse.mutable" })
        ds.record_row("a",[["x", "acrasial", 0]])
        ds.record_row("b",[["x", "blaternation", 0]])
        ds.record_row("c",[["x", "citharize", 0]])
        ds.record_row("d",[["x", "drollic", 0]])
        ds.record_row("e",[["x", "egrote", 0]])
        ds.commit()

        res = mldb.query('''
            select x LIKE '%' as v
            from sample
        ''')

        expected = [["_rowName","v"],["d",1],["a",1],["b",1],["e",1],["c",1]]
        self.assertEqual(res, expected)

        res = mldb.query('''
            select x LIKE '%o%' as v
            from sample
        ''')

        expected = [["_rowName","v"],["d",1],["a",0],["b",1],["e",1],["c",0]]
        self.assertEqual(res, expected)

        res = mldb.query('''
            select x NOT LIKE '%o%' as v
            from sample
        ''')

        expected = [["_rowName","v"],["d",0],["a",1],["b",0],["e",0],["c",1]]
        self.assertEqual(res, expected)

        res = mldb.query('''
            select x LIKE '______' as v
            from sample
        ''')

        expected = [["_rowName","v"],["d",0],["a",0],["b",0],["e",1],["c",0]]
        self.assertEqual(res, expected)

        res = mldb.query('''
            select x LIKE '___ll__' as v
            from sample
        ''')

        expected = [["_rowName","v"],["d",1],["a",0],["b",0],["e",0],["c",0]]
        self.assertEqual(res, expected)

        res = mldb.query('''
            select x LIKE '%t_' as v
            from sample
        ''')        

        expected = [["_rowName","v"],["d",0],["a",0],["b",0],["e",1],["c",0]]
        self.assertEqual(res, expected)

    def test_like_in_where(self):

        ds = mldb.create_dataset({ "id": "sample2", "type": "sparse.mutable" })
        ds.record_row("a",[["x", "acrasial", 0]])
        ds.record_row("b",[["x", "blaternation", 0]])
        ds.record_row("c",[["x", "citharize", 0]])
        ds.record_row("d",[["x", "drollic", 0]])
        ds.record_row("e",[["x", "egrote", 0]])
        ds.commit()

        res = mldb.query('''
            select x
            from sample2
            where x LIKE '%o%'
        ''')

        expected = [["_rowName","x"],["d","drollic"],["b","blaternation"],["e","egrote"]]
        self.assertEqual(res, expected)

    def test_like_special(self):

        ds = mldb.create_dataset({ "id": "sample3", "type": "sparse.mutable" })
        ds.record_row("a",[["x", "acra[sial", 0]])
        ds.record_row("b",[["x", "blate*rnation", 0]])
        ds.record_row("c",[["x", "cit.harize", 0]])
        ds.record_row("d",[["x", "dro|llic", 0]])
        ds.record_row("e",[["x", "eg(ro)te", 0]])
        ds.commit()       

        res = mldb.query('''
            select x
            from sample3
            where x LIKE '%[____'
        ''')

        expected = [["_rowName","x"],["a","acra[sial"]]
        self.assertEqual(res, expected)

        res = mldb.query('''
            select x
            from sample3
            where x LIKE '%*%'
        ''')


        expected = [["_rowName","x"],["b","blate*rnation"]]
        self.assertEqual(res, expected)

        res = mldb.query('''
            select x
            from sample3
            where x LIKE '___.%'
        ''')

        expected = [["_rowName","x"],["c","cit.harize"]]
        self.assertEqual(res, expected)

        res = mldb.query('''
            select x
            from sample3
            where x LIKE '__o|ll_%'
        ''')

        expected = [["_rowName","x"],["d","dro|llic"]]
        self.assertEqual(res, expected)

        res = mldb.query('''
            select x
            from sample3
            where x LIKE '%(__)%'
        ''')

        expected = [["_rowName","x"],["e","eg(ro)te"]]
        self.assertEqual(res, expected)

    def test_like_number(self):

        ds = mldb.create_dataset({ "id": "sample4", "type": "sparse.mutable" })
        ds.record_row("a",[["x", 0, 0]])
        ds.record_row("b",[["x", 12345, 0]])
        ds.record_row("c",[["x", 12345.00, 0]])
        ds.commit()       

        with self.assertRaises(mldb_wrapper.ResponseException) as re:
            res = mldb.query('''
                select x
                from sample4
                where x LIKE '12345%'
            ''')

mldb.run_tests()
