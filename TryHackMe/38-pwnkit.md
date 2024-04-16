# PwnKit
> https://tryhackme.com/r/room/pwnkit

CVE-2021-4034 (colloquially dubbed "Pwnkit") is a terrifying Local Privilege Escalation (LPE) vulnerability, located in the "Polkit" package installed by default on almost every major distribution of the Linux operating system (as well as many other *nix operating systems). In other words, it affects virtually every mainstream Linux system on the planet.

This room will provide an overview of the vulnerability, as well as recommendations to patch affected systems. A vulnerable machine has also been attached to allow you to try the vulnerability for yourself!

**Overview**

CVE-2021-4034 (aka "pwnkit") was discovered by researchers at Qualys and announced in January 2022; the technical security advisory for this vulnerability can be found here. The vulnerability has existed in every version of the "Policy Toolkit" (or, Polkit) package since it was first released in 2009 and allows any unprivileged attacker to easily obtain full administrative access over any Linux machine with the Polkit package installed. Unfortunately, Polkit is installed by default on most distributions of Linux, making this vulnerability extremely widespread.

The ease of exploitation and ubiquitous nature of Polkit make this an absolutely devastating vulnerability; however, fortunately it is not exploitable remotely, making Pwnkit purely a local privilege escalation (LPE) vulnerability.

**What is Polkit?**

Before we look at the vulnerability directly, it helps to understand what Polkit actually is.

Polkit is part of the Linux authorisation system. In effect, when you try to perform an action which requires a higher level of privileges, Polkit can be used to determine whether you have the requisite permissions. It is integrated with systemd and is much more configurable than the traditional sudo system. Indeed, it is sometimes referred to as the "sudo of systemd", providing a granular system with which to assign permissions to users.

When interacting with polkit we can use the pkexec utility — it is this program that contains the Pwnkit vulnerability. As an example of using the utility, attempting to run the useradd command through pkexec in a GUI session results in a pop-up asking for credentials:
`pkexec useradd test1234`

To summarise, the policy toolkit can be thought of as a fine-grained alternative to the simpler sudo system that you may already be familiar with.

---

**The Vulnerability**

As mentioned previously, the Pwnkit vulnerability exists in the pkexec utility — the primary front-end to the Polkit system. We won't go into too much detail here in the interests of readability; however, you are encouraged to read through the Qualys Security Advisory for a full technical explanation of the vulnerability.

The short version is this: versions of pkexec released prior to the patch don't handle command-line arguments safely, which leads to an "out-of-bounds write" vulnerability, allowing an attacker to manipulate the environment with which pkexec is run. This is all you really need to know, but for a slightly more technical explanation, read on!

More specifically, pkexec attempts to parse any command-line arguments that we pass it using a for-loop, starting at an index of 1 to offset the name of the program and obtain the first real argument (e.g. if we entered pkexec bash, then as pkexec is the name of the program, it would be argument 0 — the actual command-line arguments start at index 1). The name of the program is irrelevant to argument parsing, so the indexing is simply offset to ignore it.

What happens, then, if we don't provide any arguments? The index is set permanently to 1!

The following pseudocode may help you to visualise this:

```
for(n=1; n < number_of_arguments; n++){
  //Do Stuff
}
```
If the number of arguments is 0 then n is never less than the number of arguments. As such, n stays equal to one and the loop is bypassed completely.

This becomes a problem later when pkexec attempts to write to the value of the argument at index n. As there are no command-line arguments, there is no argument at index n — instead the program overwrites the next thing in memory, which just so happens to be the first value in the list of environment variables when the program is called using a C function called `execve()`. In other words, by passing pkexec a null list of arguments, we can force it to overwrite an environment variable instead!

For context: certain "dangerous" environment variables are removed by the operating system when you attempt to run a program that has the SUID bit set (as pkexec does by necessity); this is to prevent attackers from being able to hijack the program as it runs with administrative permissions. Using the out-of-bounds write, we are able to re-introduce our choice of these dangerous environment variables by tricking pkexec into adding it for  us. There are a variety of different ways to abuse this, all leading to code execution as the root user.

In which Polkit utility does the Pwnkit vulnerability reside?
pkexec



