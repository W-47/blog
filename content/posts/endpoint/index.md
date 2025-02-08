---
title: "Endpoint Security"
date: 2023-12-31
layout: "simple"
categories: [Blue team]
tags: [SOC analyst, endpoints]
image: https://i.ibb.co/cgYN2Kr/th-3134630742.jpg
---

Hello guys and today I will share with you some breif points that I was able to come up with on Endpoint security where we will talk about how endpoint security works and the various types of endpoint security solutions. With that said let us get into it.

# Introduction

Endpoints are physical devices that connect to and exchange information with a computer network. Some of these examples include, mobile devices, desktop computers, virtual machines, embedded devices and servers. This can then lead to defining what endpoint security.
Endpoint security or rather endpoint protection is the cyber security approach to defending endpoints

# How Endpoint security works

Endpoint security solutions offer a centralized management console from which administrators can connect to their network to monitor, protect, investigate and respond to incidents. This is accomplished by leveraging either an on-premises, hybrid or cloud approach

The traditional approach is often used to describe on-premises security posture that is reliant ona locally hosted data center from which security is delivered. The data center acts as a hub for the management console to reach out to the endpoints through an agent to provide security.

Another approach is a cloud-native solution built in and for the cloud. Admins can remotely monitor and manage endpoints through a centralized management console that lives in the cloud and connects to devices remotely through an agent on the endpoint. Cloud based solutions offer scalability and flexibility and are easy to install, integrate and manage

In recent years some endpoint protection solutions have shifted to a hybrid solution taking a legacy architecture design and the cloud to gain some cloud capabilities.

# Types of Endpoint security
## Endpoint Protection Platform (EPP)
An EPP solution is a preventative tool that perfoms point-in-time protection by inspecting and scanning files once they are on a network. The most common encpoint protection is a traditional antivirus (AV) solution.
AV solutions encompasses antimalware capabilities, which are mainly designed to protect against signature-based attacks

## Endpoint detection and Remediation (EDR)

An EDR solution goes beyond simple point-in-time detection mechanisms. It instead continously monitors all files and applications that enter a device. They provide more detailed visibility and analysis for threat investigation. This solution detect threats beyond signature-based attacks, fileless malware, ransomware, polymorphic attacks.

## Extended detection and Response (XDR)

XDR extends the range of EDR to encompass more deployed security solutions with a broader capability using the latest technologies to provide a higher visibility and collects and correlates threat information while employing analytics and automation to help detect current cyber attacks

This will be the beginning of my blue team journey and I will post notes a long the way. Enjoy.