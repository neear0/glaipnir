# Choosing a Windows backend

glaipnir has two ways to sandbox a program on Windows. Both keep the program away from most of your
files and from the rest of your system, but they make different trade-offs. This page explains them
without assuming you know how Windows security works.

If you are unsure: **start with `app_container`** (the default). Switch to `restricted_token` only when
a tool you need does not work in `app_container`.

## The short version

|                                              | `app_container` (default) | `restricted_token` |
|----------------------------------------------|---------------------------|--------------------|
| Can read your personal folders               | No                        | No, except folders that were shared with all users (see below) |
| Can read data drives such as `D:\`           | No                        | **Yes**, usually |
| Can change files outside its workspace       | No (unless you allow it)  | No (unless you allow it) |
| Can block internet access                    | Yes (`network.mode = "none"`) | **No**, it always has internet access |
| Tools that write to `NUL` (parts of git, many scripts) | Fail            | Work |
| Starting programs by full path (`C:\...\x.exe`) | Fails                  | Works |
| Needs administrator rights                   | No                        | No |

## What "sandbox" means here

A program you run normally can do everything your Windows account can do: read your documents, your
browser data, your saved passwords, change any of your files, and talk to the internet. glaipnir starts
the program with far fewer rights, so a buggy or misbehaving AI agent can only touch what you hand it:
its workspace and the folders you list in the policy.

## `app_container`

Windows has a built-in "app container" mechanism, the same one used to isolate Microsoft Store apps.
A program inside one is treated as a separate, nearly powerless identity. It cannot see your files,
your other drives, or the network unless glaipnir explicitly allows it.

**Downside:** some ordinary tools break inside it, because a few Windows features are not available to
app containers at all. The most common one is the `NUL` device (the Windows "throw this output away"
file), which many scripts and parts of git use. Programs also cannot be started by their full path,
only by name through `PATH`.

## `restricted_token`

Here the program runs as a weakened copy of **your own account**: all special privileges removed,
administrator rights removed, marked "low integrity" so it cannot change normal files, and only able to
use files that glaipnir grants to its session. Because it is still "you", ordinary tools work.

**Downsides, honestly:**

1. **It can read anything that every user on the PC may read.** Windows only lets the program start if
   it keeps membership in the built-in "Users" group, and anything readable by "Users" is therefore
   readable by the sandbox. Your personal folders are normally *not* readable by "Users", but data
   drives such as `D:\` usually *are*. If you keep code, documents or backups on another drive, assume
   the program can read them.
2. **It always has internet access.** Without administrator rights glaipnir cannot block network
   traffic for this kind of process, so a policy with `network.mode = "none"` is refused rather than
   silently ignored. A program that can read your files and reach the internet could send those files
   somewhere.
3. **Personal folders that were shared with all users.** Sometimes you, an installer or a sync tool give
   "Users" access to a folder inside your profile (for example Desktop or Documents). glaipnir checks
   your profile (three levels deep) before every run and, if it finds such a folder, **stops and asks you
   what to do**. That is what the `exposed_folders` setting is for.

## The `exposed_folders` setting

Only used with `backend = "restricted_token"`. Put it under `[sandbox]`:

```toml
[sandbox]
backend = "restricted_token"
exposed_folders = "refuse"   # or "warn" or "deny"
```

- **`"refuse"` (default)** – glaipnir does not run the program. It prints the folders it found, why, and
  your options. Nothing on your PC is changed.
- **`"warn"`** – the program runs and **can read those folders**. glaipnir prints a reminder on every run.
  Choose this only if the folders contain nothing private.
- **`"deny"`** – glaipnir adds a rule to each of those folders that blocks this one sandbox session, and
  removes the rule again when you delete the session (`glaipnir session delete <id>`). Windows has to
  update the permissions of every file inside the folder, so the first run (and the clean-up) can take a
  long time for big folders. If glaipnir is killed in the middle, the rule stays until you run
  `glaipnir session delete` for that session. Only the sandbox is blocked; you and your other programs are
  not affected.

There is a fourth option that needs no setting: remove the "Users" permission from the folder yourself
(right-click the folder, Properties, Security, or `icacls "<folder>" /remove:g *S-1-5-32-545`). This is the
cleanest fix, but anything that relied on other accounts reading that folder will lose access too.

## Which one should I use?

- Running an AI coding agent on a project, offline: **`app_container`** with `network.mode = "none"`.
- The agent's tools fail with "Access is denied" on `NUL` or similar: **`restricted_token`**, and keep
  in mind it can read other drives and use the internet. Do not use it on a machine where other drives
  hold things you would not want uploaded.
- You need filtered network access (only certain websites): not available yet on Windows; see the roadmap
  in the README.
