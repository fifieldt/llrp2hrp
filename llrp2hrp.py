#!/usr/bin/env python

import argparse
import logging
import SocketServer
import struct
from binascii import hexlify
from sllurp.llrp import LLRPMessage
from sllurp.llrp_proto import LLRPError
from hrp import HRP, const, exception
from hrp.tag import TidReadParameter, TagAddress, MatchParameter

HOST = ''
PORT = 5084

logger = logging.getLogger(__name__)

message_seq = 0


class LLRPMessageHandler(SocketServer.StreamRequestHandler):

    def __init__(self, request, client_address, server):
        self.request = request
        self.client_address = client_address
        self.server = server

        # for partial data transfers
        self.expectingRemainingBytes = 0
        self.partialData = ''
        logger.debug('in LLRPMessageHandler')

        self.setup()
        try:
            self.handle()
        finally:
            self.finish()

    def handle(self):
        logger.debug('in handle')
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
                                'Microseconds': 0
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
                logger.warning('Too few bytes (%d) to unpack message header',
                               len(data))
                self.partialData = data
                self.expectingRemainingBytes = \
                    LLRPMessage.full_hdr_len - len(data)
                break

            logger.debug('expect %d bytes (have %d)', msg_len, len(data))

            if len(data) < msg_len:
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
                    self.handleMessage(lmsg, message_seq)
                    message_seq = message_seq + 1
                    data = self.request.recv(1024)
                except LLRPError:
                    logger.exception('Failed to decode LLRPMessage; '
                                     'will not decode %d remaining bytes',
                                     len(data))
                    break

        message_seq = 1

    def handleMessage(self, lmsg, message_seq):
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
                                 'HasUTCClockCapability': 0,
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
            msg_dict = {'ADD_ROSPEC_RESPONSE': {
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

            # send some tags!
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
                                }
                            }, {
                                'Type': 240,
                                'EPCData': {
                                    'Type': 241,
                                    'EPCLengthBits': 96,
                                    'EPC': '001060310000000000000882'
                                }
                            }],
                        }}
            llrp_msg = LLRPMessage(msgdict=msg_dict)
            self.request.send(llrp_msg.msgbytes)

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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-r',
        '--reader',
        help='IP address of reader'
    )
    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG)
    SocketServer.TCPServer.allow_reuse_address = True
    server = SocketServer.TCPServer((HOST, PORT), LLRPMessageHandler)
    logger.info("LLRP server running...")
    server.serve_forever()
    server.server_close()


if __name__ == '__main__':
    main()
