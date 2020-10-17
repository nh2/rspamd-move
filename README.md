# rspamd-move

Useful for re-classifying all your existing emails with [rspamd](https://rspamd.com/doc/quickstart.html#using-rspamc-console-routine).

Runs [`rspamc`](https://rspamd.com/doc/quickstart.html#using-rspamc-console-routine) over files/directories and places detected spam/ham in specified output directores.


## Example usage

The following command classifies all emails in the default `Inbox` of a [Maildir](https://en.wikipedia.org/wiki/Maildir) of user `myuser@example.com` and moves them into the specified directories (you may need to create the directories first, e.g. using an email client or manually):

```
./rspamd-move.py \
  --emails /var/vmail/example.com/myuser/cur \
  --action-to-dir reject /var/vmail/example.com/myuser/.Spam-reject/cur \
  --action-to-dir greylist /var/vmail/example.com/myuser/.Spam-greylist/cur \
  --action-to-dir 'add header' /var/vmail/example.com/myuser/.Spam-add-header/cur \
  --log-level INFO \
  --threads 16
```

See `--help` for more options.
