# Design (Work-in-Progress)

Inner-class or nested-class is useful for bunching up a set of similar methods into using the same IscBoolean
class. (***DONE***)

Builder design is useful for doing things like `namedconf().view('red').recursion().get()` (a form of chaining)

Dataclass is useful for nesting ISC Bind9 `zone` statement(s) into either under `view` or under `options` clause.

Polymorphic class is useful for overextending a class to having additional feature set (such as non-binary values along
with `IscBoolean` class' `True`/`False` and `yes`/`no`.)

# Method

subclass isc_boolean()

subclass print()

```python
class A:
    def __init__(self):
        print("A.__init__()")


class B(A):
    def __init__(self):
        print("B.__init__()")
        super(B, self).__init__()
```

