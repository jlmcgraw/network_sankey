class Index(list):
    """Minimal stub of pandas.Index."""

    def __init__(self, data=None):
        super().__init__(data or [])


class Series:
    def __init__(self, data):
        self.data = list(data)

    def __iter__(self):
        return iter(self.data)

    def __len__(self):
        return len(self.data)

    def __eq__(self, other):
        return Series([x == other for x in self.data])

    def sum(self):
        total = 0
        for x in self.data:
            if isinstance(x, (int, float)):
                total += x
        return total

    def apply(self, func):
        return Series([func(x) for x in self.data])

    def map(self, mapper):
        if callable(mapper):
            return Series([mapper(x) for x in self.data])
        return Series([mapper.get(x) for x in self.data])

    def dropna(self):
        return Series([x for x in self.data if x is not None])

    def unique(self):
        seen = []
        for x in self.data:
            if x not in seen:
                seen.append(x)
        return seen

    def tolist(self):
        return list(self.data)

    def astype(self, _type):
        if _type in (str, "str"):
            return Series([None if x is None else str(x) for x in self.data])
        return self

class _LocIndexer:
    def __init__(self, df):
        self.df = df

    def __getitem__(self, key):
        rows, column = key
        if isinstance(rows, Series):
            mask = rows.data
        else:
            mask = rows
        filtered = [row for row, m in zip(self.df._data, mask) if m]
        return Series([row.get(column) for row in filtered])

class _ILocIndexer:
    def __init__(self, df):
        self.df = df

    def __getitem__(self, idx):
        return self.df._data[idx]

class DataFrame:
    def __init__(self, data=None):
        if isinstance(data, list):
            self._data = [dict(row) for row in data]
            self.columns = list(data[0].keys()) if data else []
        elif isinstance(data, dict):
            length = max((len(v) for v in data.values()), default=0)
            self._data = []
            for i in range(length):
                row = {k: (v[i] if i < len(v) else None) for k, v in data.items()}
                self._data.append(row)
            self.columns = list(data.keys())
        else:
            self._data = []
            self.columns = []

    @property
    def empty(self):
        return not self._data

    def __contains__(self, key):
        return key in self.columns

    def __getitem__(self, key):
        if isinstance(key, str):
            return Series([row.get(key) for row in self._data])
        elif isinstance(key, list):
            return DataFrame([{k: row.get(k) for k in key} for row in self._data])
        raise TypeError

    def __setitem__(self, key, value):
        if isinstance(value, Series):
            values = value.data
        else:
            values = list(value)
        if len(self._data) < len(values):
            for _ in range(len(values) - len(self._data)):
                self._data.append({c: None for c in self.columns})
        if key not in self.columns:
            self.columns.append(key)
            for row in self._data:
                row.setdefault(key, None)
        for i, row in enumerate(self._data):
            row[key] = values[i] if i < len(values) else None

    def copy(self):
        return DataFrame([dict(r) for r in self._data])

    @property
    def loc(self):
        return _LocIndexer(self)

    @property
    def iloc(self):
        return _ILocIndexer(self)

    def dropna(self, subset=None):
        subset = subset or self.columns
        rows = [r for r in self._data if all(r.get(c) is not None for c in subset)]
        return DataFrame(rows)

    def rename(self, *, columns=None):
        if not columns:
            return self.copy()
        rows = []
        for row in self._data:
            new_row = {columns.get(k, k): v for k, v in row.items()}
            rows.append(new_row)
        df = DataFrame(rows)
        return df

    def groupby(self, keys, dropna=False):
        if isinstance(keys, str):
            keys = [keys]
        return DataFrameGroupBy(self, keys, dropna)

    def query(self, expr):
        expr = expr.strip()
        if '==' in expr:
            col, val = expr.split('==')
            col = col.strip()
            val = val.strip().strip('"\'')
            rows = [r for r in self._data if str(r.get(col)) == val]
            return DataFrame(rows)
        raise NotImplementedError

    def astype(self, mapping):
        return self

    def reset_index(self):
        return self

    def __len__(self):
        return len(self._data)

    @property
    def index(self):
        return Index(range(len(self._data)))

class DataFrameGroupBy:
    def __init__(self, df, keys, dropna):
        self.df = df
        self.keys = keys
        self.dropna = dropna

    def __getitem__(self, column):
        return DataFrameGroupByColumn(self, column)

class DataFrameGroupByColumn:
    def __init__(self, groupby, column):
        self.groupby = groupby
        self.column = column

    def sum(self):
        result = {}
        for row in self.groupby.df._data:
            key = tuple(row.get(k) for k in self.groupby.keys)
            if self.groupby.dropna and any(v is None for v in key):
                continue
            val = row.get(self.column)
            if val is None:
                continue
            result[key] = result.get(key, 0) + val
        rows = []
        for key, val in result.items():
            row = {k: key[i] for i, k in enumerate(self.groupby.keys)}
            row[self.column] = val
            rows.append(row)
        return DataFrame(rows)

def concat(objs, ignore_index=False):
    if not objs:
        return DataFrame()
    if all(isinstance(o, Series) for o in objs):
        data = []
        for o in objs:
            data.extend(o.data)
        return Series(data)
    else:
        data = []
        for df in objs:
            data.extend(df._data)
        return DataFrame(data)

def notnull(value):
    return value is not None
