# Google Dorking
> https://tryhackme.com/room/googledorking

## Intro 

Search Engine Optimisation or SEO is a prevalent and lucrative topic in modern-day search engines. In fact, so much so, that entire businesses capitalise on improving a domains SEO “ranking”. At an abstract view, search engines will “prioritise” those domains that are easier to index. There are many factors in how “optimal” a domain is - resulting in something similar to a point-scoring system.



To highlight a few influences on how these points are scored, factors such as:

• How responsive your website is to the different browser types I.e. Google Chrome, Firefox and Internet Explorer - this includes Mobile phones!

• How easy it is to crawl your website (or if crawling is even allowed ...but we'll come to this later) through the use of "Sitemaps"

• What kind of keywords your website has (i.e. In our examples if the user was to search for a query like “Colours” no domain will be returned - as the search engine has not (yet) crawled a domain that has any keywords to do with “Colours”



There is a lot of complexity in how the various search engines individually "point-score" or rank these domains - including vast algorithms. Naturally, the companies running these search engines such as Google don't share exactly how the hierarchic view of domains ultimately ends up. Although, as these are businesses at the end of the day, you can pay to advertise/boost the order of which your domain is displayed.

Tools:
- https://web.dev/about/
- https://pagespeed.web.dev/

But...Who or What Regulates these "Crawlers"?

Aside from the search engines who provide these "Crawlers", website/web-server owners themselves ultimately stipulate what content "Crawlers" can scrape. Search engines will want to retrieve everything from a website - but there are a few cases where we wouldn't want all of the contents of our website to be indexed! Can you think of any...? How about a secret administrator login page? We don't want everyone to be able to find that directory - especially through a google search.

Introducing Robots.txt... 

### Robots.txt
Robots.txt

Similar to "Sitemaps" which we will later discuss, this file is the first thing indexed by "Crawlers" when visiting a website.


But what is it?

This file must be served at the root directory - specified by the webserver itself. Looking at this files extension of .txt, its fairly safe to assume that it is a text file.

The text file defines the permissions the "Crawler" has to the website. For example, what type of "Crawler" is allowed (I.e. You only want Google's "Crawler" to index your site and not MSN's). Moreover, Robots.txt can specify what files and directories that we do or don't want to be indexed by the "Crawler".

A very basic markup of a Robots.txt is like the following:
```
User-agent: *
Allow: /

Sitemap: http://mywebsite.com/sitemap.xml
```
Here we have a few keywords...
|   Keyword  |                                                               Function                                                              |
|:----------:|:-----------------------------------------------------------------------------------------------------------------------------------:|
| User-agent |          Specify the type of "Crawler" that can index your site (the asterisk being a wildcard, allowing all "User-agents"          |
|    Allow   |                                   Specify the directories or file(s) that the "Crawler" can index                                   |
|  Disallow  |                                  Specify the directories or file(s) that the "Crawler" cannot index                                 |
|   Sitemap  | Provide a reference to where the sitemap is located (improves SEO as previously discussed, we'll come to sitemaps in the next task) |

In this case:

1. Any "Crawler" can index the site

2. The "Crawler" is allowed to index the entire contents of the site

3. The "Sitemap" is located at http://mywebsite.com/sitemap.xml
Say we wanted to hide directories or files from a "Crawler"? Robots.txt works on a "blacklisting" basis. Essentially, unless told otherwise, the Crawler will index whatever it can find.

```
User-agent: *
Disallow: /super-secret-directory/
Disallow: /not-a-secret/but-this-is/

Sitemap: http://mywebsite.com/sitemap.xml
```
In this case:

1. Any "Crawler" can index the site

2. The "Crawler" can index every other content that isn't contained within "/super-secret-directory/".

Crawlers also know the differences between sub-directories, directories and files. Such as in the case of the second "Disallow:" ("/not-a-secret/but-this-is/")

The "Crawler" will index all the contents within "/not-a-secret/", but will not index anything contained within the sub-directory "/but-this-is/".

3. The "Sitemap" is located at http://mywebsite.com/sitemap.xml


**What if we Only Wanted Certain "Crawlers" to Index our Site?**

We can stipulate so, such as in code below:
```
User-agent: Googlebot
Allow: /

User-agent: msnbot
Disallow: /
```

1. The "Crawler" "Googlebot" is allowed to index the entire site ("Allow: /")

2. The "Crawler" "msnbot" is not allowed to index the site (Disallow: /")

**How about Preventing Files From Being Indexed?**

Whilst you can make manual entries for every file extension that you don't want to be indexed, you will have to provide the directory it is within, as well as the full filename. Imagine if you had a huge site! What a pain...Here's where we can use a bit of regexing.


```
User-agent: *
Disallow: /*.ini$

Sitemap: http://mywebsite.com/sitemap.xml
```

In this case:

1. Any "Crawler" can index the site

2. However, the "Crawler" cannot index any file that has the extension of .ini within any directory/sub-directory using ("$") of the site.

3. The "Sitemap" is located at http://mywebsite.com/sitemap.xml

Why would you want to hide a .ini file for example? Well, files like this contain sensitive configuration details. Can you think of any other file formats that might contain sensitive information?


### Sitemaps

Sitemaps

Comparable to geographical maps in real life, “Sitemaps” are just that - but for websites!

“Sitemaps” are indicative resources that are helpful for crawlers, as they specify the necessary routes to find content on the domain. The below illustration is a good example of the structure of a website, and how it may look on a "Sitemap":

![sitemap]()




Why are "Sitemaps" so Favourable for Search Engines?

Search engines are lazy! Well, better yet - search engines have a lot of data to process. The efficiency of how this data is collected is paramount. Resources like "Sitemaps" are extremely helpful for "Crawlers" as the necessary routes to content are already provided! All the crawler has to do is scrape this content - rather than going through the process of manually finding and scraping. Think of it as using a wordlist to find files instead of randomly guessing their names!





