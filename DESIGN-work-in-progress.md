
# Design Patterns (Python-based)


## Factory Pattern

Now for the wrapper of each EBNF.

Given that `PyParsing` portion of `named.conf` EBNF is 100% completed, it would make most sense to wrap each individual `ParseElement` (aka EBNF) of each clause and statement with a new Python wrapper class so that each EBNF will have their own:

* parser of `named.conf`
* loader of Python token (mixed `dict`/`list`) variable
* outputter
* versioning
  * validation
  * verification
  * constraint checking
* upgrader/downgrader

Wrapping around EBNF as a syntax unit makes maintenance much easier for all things specific to that clause or statement keyword.

Hence, it is imperative to prototype all of the above carefully before engaging in massive wrapping of some 2,400-odd EBNFs.

### Parser - Factory Pattern

Need to weight in on whether to break-up the existing ParseElement classes and re-integrate into a master wrapper class, one has to ask the following:

* Pros of a Master Wrapper Class
  * How much harder is it to maintain if `ParseElement`s were broken up and reintegrated into a wrapper class covering its additional methods?
  * Need to rework all interface design on all `ParserElement` classes for handling of joining `ParseElement` into the new wrapper class just to construct its master parser.
  * Should the token variables be dispersed throughout each of its own class tree?  Or maintained as a huge master token variable at the parent class?

* Cons of a Master Wrapper Class
  * How much simpler is it to just start a new wrapper class and leave `PyParsing` alone?  Are there any benefits to having this standalone Python token variable containing many `dict`/`list` elements?

* Pros of keeping `ParseElement` classes together
  * Now have a single place to maintain a single EBNF syntax

* Cons of keeping `ParseElement` classes together
  * Now have two separate places to maintain a single EBNF syntax

### Loader - Factory Pattern
### Outputter - Factory Pattern
### Versioning - Factory Pattern

## Nested-Class Pattern

Inner-class or nested-class pattern is useful for bunching up a set of similar methods into using the same IscBoolean
class. (***DONE***)


## Builder Pattern

Builder pattern is useful for doing things like `namedconf().view('red').recursion().get()` (a form of Python method-chaining).  May be possible to extend to be using a more simplified variant of `namedconf.view['red'].recursion.get()`, but this is NOT important now as getting the generated output of `named.conf` from its token variable.


## Dataclass Pattern

Dataclass is useful for nesting ISC Bind9 `zone` statement(s) into either under `view` or under `options` clause.


## Polymorphic Pattern

Polymorphic class is useful for overextending a class to having additional feature set (such as non-binary values along
with `IscBoolean` class' `True`/`False` and `yes`/`no`.)


# Versioning

Because the configuration file of `named.conf` comes in various syntax due to evolution of new and obsoleted features, versioning support must be incorporated.

There is several orthogonal aspects of versioning here:

* detection of current version (free-floating)
  * detecting conflict of clause/statement keywords
  * reporting supported range of versions
* user-defined version (fixed variant)
  * report of ignored clause/statement keywords
  * requires version argument at Python class-level
* reversioning (upgrade or downgrade)
  * report of ignored clause/statement keywords
  * requires version argument at Python class-level

## Free-Floating Versioning

The `PyParsing` handles all versions of ISC Bind9 from `8.1` to `9.19.1` but version-specific defaulting is discussed under later `Default Values` section. 

Minimum and maximum version variables are in the parent class along with `get_supported_version_range` method.

## Fixed Versioning

The user may specify a specific version before loading of the `named.conf` thus may cause error due to version-mismatch, but it would assure the user of its correct version needed for their end-use (such as analysis or validation).   This is not fully-implemented.

Would have a `set_desired_version()` and `get_desired_version()` methods in the parent class to be made accessible and readable by all of its subclasses.

## Reversioning

A future capability set may allow for reversioning of the `named.conf` in form of either upgrade or downgrade.

Such reversioning would entail reading the `named.conf` file at a specific or free-floating version, then outputting at a specific version.

This calls for a reconstruction of `PyParsing` given a specific version.  We hope to be able to do the following:

```python
    import bind9_parser
    toplevel_config = process_entire_file_content(named_config)
    nc_parser = bind9_parser.clause_statements \
                     .setDebug(g_verbosity) \
                     .setParseAction(myAction2) \
                     .ignore(pp.cStyleComment) \
                     .ignore(pp.cppStyleComment) \
                     .ignore(pp.pythonStyleComment)
    
    nc_parser.set_version('9.6.1')
    nc_tokens = nc_parser.parseString(
        toplevel_config, 
        parseAll=True)
    
    # Output a different version
    nc_output = bind9_outputter()
    nc_output.set_version('9.19.1')
    nc_output.read_tokens(nc_tokens)
    nc_output.output_file('new-named.conf')
```

