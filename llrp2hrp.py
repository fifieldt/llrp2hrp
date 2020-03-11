#!/usr/bin/env python

import argparse
import codecs
import lcddriver
import logging
import SocketServer
import socket
import struct
import time
from binascii import hexlify
from sllurp.llrp import LLRPMessage
from sllurp.llrp_proto import LLRPError
from hrp import HRP, const, exception
from hrp.exception import HRPFrameError, HRPNetworkError
from hrp.tag import TidReadParameter, TagAddress, MatchParameter

HOST = ''
PORT = 5084
HRP_HOST = '192.168.100.116'
HRP_PORT = 9090
HRP_TAG_FILTER_MS = 100
HRP_TAG_FILTER_RSSI = 0
KEEPALIVE_THRESHOLD = 3
BACKOFF_TIME = 30
HAVE_LCD = True


# Don't try connecting the HRP reader
FAKE_MODE = False

logger = logging.getLogger(__name__)

try:
    display = lcddriver.lcd()
    display.lcd_clear()
except:
    HAVE_LCD = False

message_seq = 0


class LLRPMessageHandler(SocketServer.StreamRequestHandler):

    def __init__(self, request, client_address, server):
        self.request = request
        self.client_address = client_address
        self.server = server

        # for partial data transfers
        self.expectingRemainingBytes = 0
        self.partialData = ''

        # set up HRP connection
        if not FAKE_MODE:
          self.hrp = HRP(ip=HRP_HOST, port=HRP_PORT, ommit_ping=False, timeout=10)
          # self.hrp.set_log_level_debug()
          logger.info('Connecting to HRP reader...')
          if HAVE_LCD:
              display.lcd_display_string('Connecting:HRP', 2)
          connected = False
          while not connected:
            try:
                self.hrp.connect()
                self.hrp_filter_time, self.hrp_rssi_threshold = self.hrp.tag_filter()
                self.hrp.tag_filter(HRP_TAG_FILTER_MS, HRP_TAG_FILTER_RSSI)
                connected = True
            except HRPFrameError:
                logger.warning('Connect didn\'t work, disconnecting and trying again ...')
                self.hrp.disconnect()
            except HRPNetworkError:
                logger.warning('Could not connect to reader, waiting and trying again ...')
                self.hrp.disconnect()
                time.sleep(BACKOFF_TIME)

        self.setup()
        try:
            self.handle()
        finally:
            self.finish()

    def handle(self):
        global message_seq
        # send a ReaderEventNotification on connection
        msg_dict = {'READER_EVENT_NOTIFICATION': {
                        'Ver': 1,
                        'Type': 63,
                        'ID': 0,
                        'ReaderEventNotificationData':
                        {
                            'UTCTimestamp':
                            {
                                'Microseconds': int(time.time() * 10e5)

                            },
                            'ConnectionAttemptEvent':
                            {
                                'Status': 'Success'
                            }
                        }
                    }}
        llrp_msg = LLRPMessage(msgdict=msg_dict)
        self.request.send(llrp_msg.msgbytes)
        message_seq = message_seq + 1
        data = self.request.recv(1024)
        logger.debug('got %d bytes from reader: %s', len(data),
                     hexlify(data))
        """
        XXX this block could be deleted
        """
        if self.expectingRemainingBytes:
            if len(data) >= self.expectingRemainingBytes:
                data = self.partialData + data
                self.partialData = ''
                self.expectingRemainingBytes -= len(data)
            else:
                # still not enough; wait until next time
                self.partialData += data
                self.expectingRemainingBytes -= len(data)
                return

        while data:
            # parse the message header to grab its length
            if len(data) >= LLRPMessage.full_hdr_len:
                msg_type, msg_len, message_id = \
                    struct.unpack(LLRPMessage.full_hdr_fmt,
                                  data[:LLRPMessage.full_hdr_len])
            else:
                # XXX
                logger.warning('Too few bytes (%d) to unpack message header',
                               len(data))
                self.partialData = data
                self.expectingRemainingBytes = \
                    LLRPMessage.full_hdr_len - len(data)
                break

            logger.debug('expect %d bytes (have %d)', msg_len, len(data))

            if len(data) < msg_len:
                # XXX
                # got too few bytes
                logger.debug("Less than an LLRP Message Size")
                self.partialData = data
                self.expectingRemainingBytes = msg_len - len(data)
                break
            else:
                # got at least the right number of bytes
                self.expectingRemainingBytes = 0
                try:
                    lmsg = LLRPMessage(msgbytes=data[:msg_len])
                    self.handle_message(lmsg, message_seq)
                    message_seq = message_seq + 1
                    data = self.request.recv(1024)
                except LLRPError:
                    logger.exception('Failed to decode LLRPMessage; '
                                     'will not decode %d remaining bytes',
                                     len(data))
                    break

        message_seq = 1

    def handle_message(self, lmsg, message_seq):
        msg_type = lmsg.getName()
        if msg_type == 'GET_SUPPORTED_VERSION':
            # we only support reader version 1, this is a v2 command.
            msg_dict = {'GET_SUPPORTED_VERSION_RESPONSE': {
                            'Ver': 1,
                            'Type': 56,
                            'ID': message_seq,
                            'CurrentVersion': 1,
                            'SupportedVersion': 1,
                            'LLRPStatus': {
                                'Type': 287,
                                'StatusCode': 'UnsupportedVersion',
                                'ErrorDescription': 'We only support v1',
                            }
                        }}
            llrp_msg = LLRPMessage(msgdict=msg_dict)
            self.request.send(llrp_msg.msgbytes)

        if msg_type == 'GET_READER_CAPABILITIES':
            msg_dict = {'GET_READER_CAPABILITIES_RESPONSE': {
                            'Ver': 1,
                            'Type': 11,
                            'ID': message_seq,
                            'LLRPStatus': {
                                'Type': 287,
                                'StatusCode': 'Success',
                                'ErrorDescription': '',
                            },
                            'GeneralDeviceCapabilities': {
                                 'MaxNumberOfAntennaSupported': 4,
                                 'CanSetAntennaProperties': 0,
                                 'HasUTCClockCapability': 1,
                                 'DeviceManufacturerName': 0,
                                 'ModelName': 7206,
                                 'ReaderFirmwareVersion': '1',
                            },
                        }}
            llrp_msg = LLRPMessage(msgdict=msg_dict)
            self.request.send(llrp_msg.msgbytes)

        if msg_type == 'GET_ROSPECS':
            # send a GET_ROSPECS_RESPONSE
            msg_dict = {'GET_ROSPECS_RESPONSE': {
                            'Ver': 1,
                            'Type': 36,
                            'ID': message_seq,
                            'LLRPStatus': {
                                'Type': 287,
                                'StatusCode': 'Success',
                                'ErrorDescription': '',
                            },
                        }}
            llrp_msg = LLRPMessage(msgdict=msg_dict)
            self.request.send(llrp_msg.msgbytes)

        if msg_type == 'DELETE_ACCESSSPEC':
            # send a DELETE_ACCESSSPEC_RESPONSE
            msg_dict = {'DELETE_ACCESSSPEC_RESPONSE': {
                            'Ver': 1,
                            'Type': 51,
                            'ID': message_seq,
                            'LLRPStatus': {
                                'Type': 287,
                                'StatusCode': 'Success',
                                'ErrorDescription': '',
                            },
                        }}
            llrp_msg = LLRPMessage(msgdict=msg_dict)
            self.request.send(llrp_msg.msgbytes)

        if msg_type == 'DELETE_ROSPEC':
            # send a DELETE_ROSPEC_RESPONSE
            msg_dict = {'DELETE_ROSPEC_RESPONSE': {
                            'Ver': 1,
                            'Type': 31,
                            'ID': message_seq,
                            'LLRPStatus': {
                                'Type': 287,
                                'StatusCode': 'Success',
                                'ErrorDescription': '',
                            },
                        }}
            llrp_msg = LLRPMessage(msgdict=msg_dict)
            self.request.send(llrp_msg.msgbytes)

        if msg_type == 'SET_READER_CONFIG':
            # send a SET_READER_CONFIG_RESPONSE
            msg_dict = {'SET_READER_CONFIG_RESPONSE': {
                            'Ver': 1,
                            'Type': 13,
                            'ID': message_seq,
                            'LLRPStatus': {
                                'Type': 287,
                                'StatusCode': 'Success',
                                'ErrorDescription': '',
                            },
                        }}
            llrp_msg = LLRPMessage(msgdict=msg_dict)
            self.request.send(llrp_msg.msgbytes)

        if msg_type == 'ADD_ROSPEC':
            # send a ADD_ROSPEC_RESPONSE
            msg_dict = {'ADD_ROSPEC_RESPONSE': {
                            'Ver': 1,
                            'Type': 30,
                            'ID': message_seq,
                            'LLRPStatus': {
                                'Type': 287,
                                'StatusCode': 'Success',
                                'ErrorDescription': '',
                            },
                        }}
            llrp_msg = LLRPMessage(msgdict=msg_dict)
            self.request.send(llrp_msg.msgbytes)

        if msg_type == 'ENABLE_ROSPEC':
            # send a ADD_ROSPEC_RESPONSE
            msg_dict = {'ENABLE_ROSPEC_RESPONSE': {
                            'Ver': 1,
                            'Type': 34,
                            'ID': message_seq,
                            'LLRPStatus': {
                                'Type': 287,
                                'StatusCode': 'Success',
                                'ErrorDescription': '',
                            },
                        }}
            llrp_msg = LLRPMessage(msgdict=msg_dict)
            self.request.send(llrp_msg.msgbytes)
            if HAVE_LCD:
                display.lcd_display_string('Reading tags  ', 2)

        if msg_type == 'ENABLE_ROSPEC' or msg_type == 'KEEPALIVE_ACK':
            # send some tags!
            if FAKE_MODE:
              timestamp = int(time.time() * 10e5)
              msg_dict = {'RO_ACCESS_REPORT': {
                              'Ver': 1,
                              'Type': 61,
                              'ID': message_seq,
                              'TagReportData': [{
                                  'Type': 240,
                                  'EPCData': {
                                      'Type': 241,
                                      'EPCLengthBits': 96,
                                      'EPC': '001060310000000000000881'
                                  },
                                  'FirstSeenTimestampUTC': {
                                    'Type': 2,
                                    'Microseconds': timestamp
                                  },
                                  'LastSeenTimestampUTC': {
                                        'Type': 4,
                                        'Microseconds': timestamp
                                  }
                              }, {
                                  'Type': 240,
                                  'EPCData': {
                                      'Type': 241,
                                      'EPCLengthBits': 96,
                                      'EPC': '001060310000000000000882'
                                  },
                                  'FirstSeenTimestampUTC': {
                                    'Type': 2,
                                    'Microseconds': timestamp
                                  },
                                  'LastSeenTimestampUTC': {
                                        'Type': 4,
                                        'Microseconds': timestamp
                                  }
                              }],
                         }}
              llrp_msg = LLRPMessage(msgdict=msg_dict)
              self.request.send(llrp_msg.msgbytes)

            if not FAKE_MODE:
              keepalive_timer = 0
              # This enables antenna port 1 and 3.
              #for tag in self.hrp.read_tag(antennas=5, match=MatchParameter(const.MATCH_EPC, 0x20, codecs.decode('01', 'hex'))):
              for tag in self.hrp.read_tag(antennas=5):
                  if tag is not None:
                    timestamp = int(time.time() * 10e5)
                    tag_hex = codecs.encode(tag.epc, 'hex')
                    logger.info("TAG FOUND: " + tag_hex)
                    msg_dict = {'RO_ACCESS_REPORT': {
                                    'Ver': 1,
                                    'Type': 61,
                                    'ID': message_seq,
                                    'TagReportData': [{
                                        'Type': 240,
                                        'EPCData': {
                                            'Type': 241,
                                            'EPCLengthBits': len(tag_hex) * 4,
                                            'EPC': tag_hex
                                        },
                                     'FirstSeenTimestampUTC': {
                                        'Type': 2,
                                        'Microseconds': timestamp
                                      },
                                     'LastSeenTimestampUTC': {
                                        'Type': 4,
                                        'Microseconds': timestamp
                                      },
                                     'PeakRSSI': {
                                        'Type': 6,
                                        'PeakRSSI': tag.rssi
                                      }}]
                                    }
                                }

                    llrp_msg = LLRPMessage(msgdict=msg_dict)
                    self.request.send(llrp_msg.msgbytes)
                  else:
                    logger.info("TIMEOUT")
                    keepalive_timer = keepalive_timer + 1
                    if keepalive_timer > KEEPALIVE_THRESHOLD:
                      self.hrp.end_read_tag = True
                      message_seq = message_seq + 1
                      msg_dict = {'KEEPALIVE': {
                                    'Ver': 1,
                                    'Type': 62,
                                    'ID': message_seq
                                  }}
                      llrp_msg = LLRPMessage(msgdict=msg_dict)
                      self.request.send(llrp_msg.msgbytes)

              self.hrp.tag_filter(self.hrp_filter_time, self.hrp_rssi_threshold)

        if msg_type == 'CLOSE_CONNECTION':
            # send a CLOSE_CONNECTION_RESPONSE
            msg_dict = {'CLOSE_CONNECTION_RESPONSE': {
                            'Ver': 1,
                            'Type': 4,
                            'ID': message_seq,
                            'LLRPStatus': {
                                'Type': 287,
                                'StatusCode': 'Success',
                                'ErrorDescription': '',
                            },
                        }}
            llrp_msg = LLRPMessage(msgdict=msg_dict)
            self.request.send(llrp_msg.msgbytes)



    def finish(self):
      if not FAKE_MODE:
        self.hrp.disconnect()
      if HAVE_LCD:
         display.lcd_display_string('Disconnected', 2)

def get_real_ip():
    """
    Attempts to get the IP address that's used for interesting things.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 53))
    ip_address = s.getsockname()[0]
    first_octet = ip_address.split('.')
    if first_octet != '127' and first_octet != '169':
        return ip_address
    else:
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-r',
        '--reader',
        help='IP address of reader'
    )
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    # get the local IP address
    real_ip = get_real_ip()
    while real_ip is False:
        real_ip = get_real_ip()
        display.lcd_display_string("No Network.", 1)
        display.lcd_display_string("Set up hotspot", 2)
        time.sleep(BACKOFF_TIME)
    if HAVE_LCD:
        display.lcd_display_string(real_ip, 1)
    SocketServer.TCPServer.allow_reuse_address = True
    server = SocketServer.TCPServer((HOST, PORT), LLRPMessageHandler)
    logger.info("LLRP server running...")
    if HAVE_LCD:
        display.lcd_display_string("LLRP server on", 2)
    server.serve_forever()
    server.server_close()


if __name__ == '__main__':
    main()
