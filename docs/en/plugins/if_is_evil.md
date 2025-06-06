# If is Evil... when used in location context

## Introduction

Directive [`if`](https://nginx.org/en/docs/http/ngx_http_rewrite_module.html#if) has problems **when used in location context**,
in some cases it doesn't do what you expect but something completely different instead.  In some cases it even segfaults.  It's generally a good idea to avoid it if possible.

The only 100% safe things which may be done inside if in a location context are:

* [`return ...;`](https://nginx.org/en/docs/http/ngx_http_rewrite_module.html#return)
* [`rewrite ... last;`](https://nginx.org/en/docs/http/ngx_http_rewrite_module.html#rewrite)

Anything else may cause unpredictable behavior, including potential SIGSEGV.

It is important to note that the behavior of if is not inconsistent, given two identical requests it will not randomly fail on one and work on the other, with proper testing and understanding ifs _can_ be used. The advice to use other directives where available still very much applies, though.

There are cases where you cannot avoid using an if, for example, if you need to test a variable which has no equivalent directive.

```nginx
if ($request_method = POST ) {
    return 405;
}
if ($args ~ post=140){
    rewrite ^ http://example.com/ permanent;
}
```

## What to do instead

Use the "return ..." or "rewrite ... last" if it suits your needs.
You can allocate additional locations and `map` if you want to set variables based on conditions.

In some cases, it's also possible to move `if`s to server level (where it's safe as only other rewrite module directives are allowed within it).

E.g., the following may be used to safely change location which will be used to process request:

```nginx
location / {
    error_page 418 = @other;
    recursive_error_pages on;

    if ($something) {
        return 418;
    }

    # some configuration
    ...
}

location @other {
    # some other configuration
    ...
}
```

In some cases it may be good idea to use embedded scripting modules ([embedded perl](https://nginx.org/en/docs/http/ngx_http_perl_module.html), or [Lua module](https://nginx-extras.getpagespeed.com/lua-scripting/)) to do the scripting.

## Examples

Here are some examples which explain why if is evil.  Don't try this at home. You were warned.

```nginx
# Here is collection of unexpectedly buggy configurations to show that
# if inside location is evil.

# only second header will be present in response
# not really bug, just how it works

location /only-one-if {
    set $true 1;

    if ($true) {
        add_header X-First 1;
    }

    if ($true) {
        add_header X-Second 2;
    }

    return 204;
}

# request will be sent to backend without uri changed
# to '/' due to if

location /proxy-pass-uri {
    proxy_pass http://127.0.0.1:8080/;

    set $true 1;

    if ($true) {
        # nothing
    }
}

# try_files wont work due to if

location /if-try-files {
     try_files  /file  @fallback;

     set $true 1;

     if ($true) {
         # nothing
     }
}

# nginx will SIGSEGV

location /crash {

    set $true 1;

    if ($true) {
        # fastcgi_pass here
        fastcgi_pass  127.0.0.1:9000;
    }

    if ($true) {
        # no handler here
    }
}

# alias with captures isn't correcly inherited into implicit nested
# location created by if

location ~* ^/if-and-alias/(?<file>.*) {
    alias /tmp/$file;

    set $true 1;

    if ($true) {
        # nothing
    }
}
```

In case you think you found an example which isn't listed here - it's a good idea to report it to the [NGINX development mailing list](http://mailman.nginx.org/mailman/listinfo/nginx-devel).

## Why this happens and still not fixed

Directive "if" is part of rewrite module which evaluates instructions imperatively.  On the other hand, NGINX configuration in general is declarative.  At some point due to users demand an attempt was made to enable some non-rewrite directives inside "if", and this lead to situation we have now.  It mostly works, but... see above.

It looks like the only correct fix would be to disable non-rewrite directives inside if completely.  It would break many configuration out there though, so wasn't done yet.

## If you still want to use if inside location context

If you read all of the above and still want to use if:

* Please make sure you actually do understand how it works.  Some basic idea may be found e.g. [here](http://agentzh.blogspot.com/2011/03/how-nginx-location-if-works.html).
* Do proper testing.

You were warned.
