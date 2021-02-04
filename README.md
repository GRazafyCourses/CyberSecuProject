# README

## Context

This work is a project for the cybersecurity classes in AGH Poland

The goal of this project is to set up a tool to test the vulnerabilities of a web application, I chose to use **DVWA** which is an application use by beginner to learn about vulnerabilities and how to patch them. 

In this tool you will find 3 options to test DVWA :

* SQL Injection
* Blind SQL Injection
* Brute Force Using a dictionary of the most common worst password on the internet.

## Set Up

step to reproduce :

* set up **dvwa** as explain here : https://github.com/digininja/DVWA I used **XAMPP** and **Windows**

* You will need to set up the files of DVWA here : `C:\xampp\htdocs\dvwa\DVWA-master`

* Launch python script `brakeDVWALow.py`


* Choose between the options :
 
        [1] For SQLInjection
        [2] For Blind SQLInjection
        [3] For BruteForce

* And follow the instruction
