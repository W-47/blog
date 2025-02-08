---
layout: simple
title: GRAPHQL
date: 2024-01-05
categories: [Web Exploitation, Graphql]
tags: [Broken Authorization]
---

Hello and welcome to another writeup, this was actually a CTF hosted by she hacks and I will take you through, how to move your way through graphql API easily. I will be using Altair which is a browser extesion, easy to set up and use.
Let us begin.

## WHAT IS GRAPHQL?

Graphql is an open source data query and manipulation language for API and a query runtime engine. A GraphQL service is created by defining types and fields on those types, then providing functions for each field on each type.

With that said we can check on the challenge. 

## FLAG1 
![1](https://i.ibb.co/ydhK5pJ/chall.png)

So on the challenge you are provided with a link which when you click on it, it displays a message that graphql is running. Okay now with our Altair extension set up we can use it. This would look like the following 

![2](https://i.ibb.co/hKJdrb2/altair.png)

So next we would ideally be needed to connect to one of the directories and we can use common directories which are `/graphql, /graphiql, /api, /api/graphql`

So basically on our left panel is where we would type in our queries and they would bring back a response on our right panel.

An example would look like 

![3](https://i.ibb.co/crZ85zb/flag1.png) 

Let us break that down, With first understanding how a query looks like 

![4](https://i.ibb.co/XxPCVYf/query.webp)

So we can see that the operation begins followed by the table and then the fields. Cool no we have a rough understanding of how a query looks like.

The flag here is the decoded message.

## FLAG 2 

So next we are going to try and get the other flag, with also playing around with some more operations. 

Using the query format explained before we can use that to create a user. We are going to use something called a mutation to do this.

A mutation is a new fundamental type included in the schema to change or write data to a Graphql service. A best practice when working with mutations is to return the object of data the mutating operation affects. That means if we change something particular in a database, we should receive the thing we updated in response as we will see shortly. 

We are going to use the mutation create user and we will see a response on the right panel
![5](https://i.ibb.co/0Bt4b0J/createuser.png)

This means that we have successfully created a user and we can use the query `getusers` to confirm this 
![6](https://i.ibb.co/9836sg1/getusers.png)

Then next we can try and use the mutation login using the credentials of the new user we have created
![7](https://i.ibb.co/FDMm9vB/login.png)

We then can get an access token which would help us with authorization and as an authorization header. We can add this token to the headers as follows

![8](https://i.ibb.co/Pw3dJQP/accesstoken.png)

`Note: Not authentication but authorization`

So then we can use the query `findnote` since the hint for challenge two required us to look for a hidden note, this we can do as;

![9](https://i.ibb.co/FqCqwf1/privesc.png)

So immediately we notice that the response is we have no permissions for this, what about we use some broken authentication.

We can do this by using the mutation `updateuser` with the query looking like so.

![10](https://i.ibb.co/qj6y4MD/admin.png)

Looking at our response we see that our first name has been changed to admin, `isadmin` has been set to true and our email has been set to `admin@gmail.com`

Cool now let us try and look for the hidden flag with our `id` set to `1` since we are `admin`. 

![11](https://i.ibb.co/QQ4N76f/flag2.png)

Nice we get a response from the service where the body contains our encoded flag

