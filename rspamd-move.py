#! /usr/bin/env python3

import argparse
import collections
import email.errors
import email.parser
import errno
import functools
import logging
import multiprocessing
import os
import re
import shutil
import subprocess


# Sets log level, from https://docs.python.org/3/howto/logging.html#logging-to-a-file
def set_log_level(log_level):
  log_level_numeric = getattr(logging, log_level.upper(), None)
  if not isinstance(log_level_numeric, int):
    raise ValueError(f'Invalid log level: {log_level}')
  logging.basicConfig(level=log_level_numeric)


# From https://rspamd.com/doc/faq.html#what-are-rspamd-actions
common_actions = [
  'discard',
  'reject',
  'greylist',
  'rewrite subject',
  'add header',
  'no action',
  'soft reject',
]


def check_positive_int(value):
  ivalue = int(value)
  if ivalue <= 0:
    raise argparse.ArgumentTypeError(f'{value} is an invalid positive int value')
  return ivalue


def make_argument_parser():
  parser = argparse.ArgumentParser(
    description='Runs rspamc over files/directories and places detected spam/ham in specified output directores.',
  )
  parser.add_argument(
    '--emails',
    required=True,
    nargs='+',
    help='Files or directories containing emails to check. Can be given repeatedly.',
  )
  common_actions_str = ', '.join(f"'{a}'" for a in common_actions)
  action_example = '--action-to-dir "no action" /var/vmail/example.com/mail/.Unclassified/cur'
  parser.add_argument(
    '--action-to-dir',
    nargs=2, metavar=('ACTION','DIR'),
    action='append',
    help=f"Move emails with rspamd 'Action: ...' output ACTION into directory DIR. Can be given multiple times, once for each action. Common actions: {common_actions_str}. Example: {action_example}",
  )
  parser.add_argument(
    '--others-dir',
    help='Move emails not matching any given --action-to-dir flag into this directory. If not given, they are not moved.',
  )
  parser.add_argument(
    '--dry-run',
    action='store_true',
    help='Do not move any files, only perform read-only actions.',
  )
  parser.add_argument(
    '--threads',
    type=check_positive_int,
    default=16,
    help='Number of threads to use.',
  )
  parser.add_argument(
    '--log-level',
    help='Set Python logging level. Example: --log-level INFO.',
  )
  return parser


action_re = re.compile(bytes(r'^Action: (.*)$', 'utf-8'), re.MULTILINE)

SenderServerInfo = collections.namedtuple('SenderServerInfo', ['ip', 'hostname'])

# Parses IP and hostname out of the `Received:` SMTP header.
# This is some guesswork, because RFC2822 doesn't actually define what can
# be in the `Received` line, only its rough format, so parsing it with
# a crude regex is the best thing we've come up with so far.
# A better parser could be taken from e.g.
#     https://github.com/rspamd/rspamd/blob/32ee6bdf5abf1e3e5b9594783d93522b01faf3e2/src/libmime/mime_headers.c#L1516
#     https://github.com/rspamd/rspamd/blob/32ee6bdf5abf1e3e5b9594783d93522b01faf3e2/test/lua/unit/received.lua#L156
#     https://github.com/rspamd/rspamd/blob/32ee6bdf5abf1e3e5b9594783d93522b01faf3e2/src/libmime/mime_headers.c#L1436-L1442
# Example contents:
#     Received: from a13-67.smtp-out.example.com (a13-67.smtp-out.example.com [192.0.2.0])
#       by mail.example.com (Postfix) with ESMTPS id 22DFB60A62
#       for <mail@example>; Thu, 30 Jul 2020 10:25:22 +0200 (CEST)
# Using Python-specific named groups; output groups:
#   - hostname
#   - ip
received_re = re.compile(r'^from\s+(\S+)\s+\((?P<hostname>\S+)\s+\[(?P<ip>[^\]]+)\]\)')

header_parser = email.parser.BytesHeaderParser()


# Extract sender's IP/hostname from the existing email so that rspamd
# can perform e.g. SPF checks on them. Without this, mails from senders
# that use a strict DMARC policy will be punished as likely spam
# (e.g. symbol `BLACKLIST_DMARC`).
#
# Unfortunately as of writing, rspamd cannot do this for us by itself,
# so this uses a crude extractor, see `received_re`.
def get_sender_server_info(full_email_with_headers):
  try:
    msg = header_parser.parsebytes(full_email_with_headers)
  except MessageError:
    logging.warning('Could not extract IP/hostname: unparseable headers')
    return None
  received_headers = msg.get_all('Received', failobj=[])
  for h in received_headers:
    m = received_re.match(h)
    if m is not None:
      return SenderServerInfo(ip=m.group('ip'), hostname=m.group('hostname'))
  received_headers_oneline = ' '.join([' '.join(x.split()) for x in received_headers])
  logging.warning(f"Could not extract IP/hostname from 'Received' header: {received_headers_oneline}")
  return None


def process(filepath, action_dirs, args):
  # Ignore the file disappearing between listdir() and open().
  try:
    f = open(filepath, 'rb')
  except IOError as ioe:
    if ioe.errno not in (errno.ENOENT,):
      raise
    logging.info(f'File vanished, ignoring: {filepath}')
  else:
    with f:
      contents = f.read()

      ssi = get_sender_server_info(contents)
      ssi_flags = [] if ssi is None else ['--ip=' + ssi.ip, '--hostname=' + ssi.hostname]

      # TODO: Disable symbol `DATE_IN_PAST` somehow, or fake the time
      output = subprocess.check_output(['rspamc', '-h', '/run/rspamd/worker-controller.sock'] + ssi_flags, input=contents)
    match = action_re.search(output)
    if not match:
      logging.warning(f'rspamc did not produce an action for email {filepath}')
    else:
      action = match.group(1)
      target_dir = action_dirs.get(action, args.others_dir or None)
      dry_run_msg = " (skipped due to --dry_run)" if args.dry_run else ""
      filename = os.path.basename(filepath)
      logging.info(f'{filename} -> {action.decode("utf-8")} -> {target_dir or "not moved"}{dry_run_msg}')
      if target_dir is not None:
        if not args.dry_run:
          shutil.move(filepath, target_dir)


def run(args):
  # Maps action (`bytes()`) -> dir given with the correspoinding flag;
  # if the flag is not given, the key is not present.
  action_dirs = {}
  for action, target_dir in args.action_to_dir:
    action_dirs[action.encode('utf-8')] = target_dir

  logging.debug('action_dirs: ' + repr(action_dirs))

  logging.info(f'Scanning {args.emails}')

  def get_filepaths(path_or_dir):
    if os.path.isdir(path_or_dir):
      d = path_or_dir
      # Don't use `os.walk()` here, so that moving a file to its own directory
      # works without creating an infinite loop.
      return [os.path.join(d, n) for n in os.listdir(d)]
    else:
      return [path_or_dir]

  filepaths = [f for e in args.emails for f in get_filepaths(e)]
  num_total = len(filepaths)

  process_partial = functools.partial(process, action_dirs=action_dirs, args=args)

  if args.threads == 1:
    for i, filename in enumerate(filepaths):
      process_partial(filename)
      logging.info(f'Done {i} of {num_total}')
  else:
    with multiprocessing.Pool(processes=args.threads) as pool:
      for i, _ in enumerate(pool.imap_unordered(process_partial, filepaths), 1):
        logging.info(f'Done {i} of {num_total}')


def main():
  args = make_argument_parser().parse_args()
  set_log_level(args.log_level)
  run(args)


if __name__ == '__main__':
  main()
