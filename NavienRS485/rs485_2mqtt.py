#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import paho.mqtt.client as mqtt
import re
from json import dumps as json_dumps
from functools import reduce
from collections import defaultdict

MQTT_USERNAME = 'eunj'
MQTT_PASSWORD = '!Teatime6699'
MQTT_SERVER = '192.168.200.68'
ROOT_TOPIC_NAME = 'rs485_2mqtt'
HOMEASSISTANT_ROOT_TOPIC_NAME = 'homeassistant'


class Device:
    def __init__(self, device_name, device_id, device_subid, device_class, child_device=None, mqtt_discovery=True, optional_info=None):
        if child_device is None:
            child_device = []
        if optional_info is None:
            optional_info = {}

        self.device_name = device_name
        self.device_id = device_id
        self.device_subid = device_subid
        self.device_unique_id = 'rs485_{}_{}'.format(self.device_id, self.device_subid)
        self.device_class = device_class
        self.child_device = child_device
        self.mqtt_discovery = mqtt_discovery
        self.optional_info = optional_info

        self.__status_messages_map = defaultdict(list)
        self.__command_messages_map = {}

    def register_status(self, message_flag, attr_name, topic_class, regex, device_name=None, process_func=lambda v: v):
        device_name = self.device_name if device_name is None else device_name
        self.__status_messages_map[message_flag].append({
            'regex': regex,
            'process_func': process_func,
            'device_name': device_name,
            'attr_name': attr_name,
            'topic_class': topic_class
        })

    def register_command(self, message_flag, attr_name, topic_class, process_func=lambda v: v):
        self.__command_messages_map[attr_name] = {
            'message_flag': message_flag,
            'attr_name': attr_name,
            'topic_class': topic_class,
            'process_func': process_func
        }

    def parse_payload(self, payload_dict):
        """
        Given payload_dict with keys: device_id, device_subid, message_flag, data, xor, add
        returns dict mapping mqtt_topic -> value
        """
        result = {}
        device_family = [self] + self.child_device
        for device in device_family:
            for status in device.__status_messages_map.get(payload_dict['message_flag'], []):
                m = re.search(status['regex'], payload_dict.get('data', ''), re.IGNORECASE)
                if m:
                    # prefer first capture group if exists
                    group_val = m.group(1) if m.groups() else m.group(0)
                    topic = '/'.join([ROOT_TOPIC_NAME, device.device_class, device.device_name, status['attr_name']])
                    try:
                        value = status['process_func'](group_val)
                    except Exception:
                        value = status['process_func'](m.group(0))
                    result[topic] = value
        return result

    def get_command_payload_byte(self, attr_name, attr_value):
        command = self.__command_messages_map.get(attr_name)
        if command is None:
            raise KeyError("Unknown command attribute: {}".format(attr_name))
        attr_value_hex = command['process_func'](attr_value)
        # build payload: f7 id subid flag 01 <data> <xor> <add>
        command_payload = ['f7', self.device_id, self.device_subid, command['message_flag'], '01', attr_value_hex]
        command_payload.append(Wallpad.xor(command_payload))
        command_payload.append(Wallpad.add(command_payload))
        hex_string = ' '.join(command_payload)
        return bytearray.fromhex(hex_string)

    def get_mqtt_discovery_payload(self):
        result = {
            '~': '/'.join([ROOT_TOPIC_NAME, self.device_class, self.device_name]),
            'name': self.device_name,
            'uniq_id': self.device_unique_id,
        }
        result.update(self.optional_info)

        for status_list in self.__status_messages_map.values():
            for status in status_list:
                result[status['topic_class']] = '/'.join(['~', status['attr_name']])

        for status in self.__command_messages_map.values():
            result[status['topic_class']] = '/'.join(['~', status['attr_name'], 'set'])

        result['device'] = {
            'identifiers': self.device_unique_id,
            'name': self.device_name
        }
        return json_dumps(result, ensure_ascii=False)

    def get_status_attr_list(self):
        return list(set([status['attr_name'] for status_list in self.__status_messages_map.values() for status in status_list]))


class Wallpad:
    _device_list = []

    def __init__(self):
        self.mqtt_client = mqtt.Client()
        self.mqtt_client.on_message = self.on_raw_message
        self.mqtt_client.on_disconnect = self.on_disconnect
        self.mqtt_client.username_pw_set(username=MQTT_USERNAME, password=MQTT_PASSWORD)
        self.mqtt_client.connect(MQTT_SERVER, 1883)

    def listen(self):
        self.register_mqtt_discovery()
        topics = [ROOT_TOPIC_NAME + '/dev/raw'] + self.get_topic_list_to_listen()
        self.mqtt_client.subscribe([(topic, 2) for topic in topics])
        self.mqtt_client.loop_forever()

    def register_mqtt_discovery(self):
        for device in self._device_list:
            if device.mqtt_discovery:
                topic = '/'.join([HOMEASSISTANT_ROOT_TOPIC_NAME, device.device_class, device.device_unique_id, 'config'])
                payload = device.get_mqtt_discovery_payload()
                self.mqtt_client.publish(topic, payload, qos=2, retain=True)

    def add_device(self, device_name, device_id, device_subid, device_class, child_device=None, mqtt_discovery=True, optional_info=None):
        device = Device(device_name, device_id, device_subid, device_class, child_device=child_device, mqtt_discovery=mqtt_discovery, optional_info=optional_info)
        self._device_list.append(device)
        return device

    def get_device(self, **kwargs):
        if 'device_name' in kwargs:
            matches = [d for d in self._device_list if d.device_name == kwargs['device_name']]
            if not matches:
                raise KeyError("Device '{}' not found".format(kwargs['device_name']))
            return matches[0]
        else:
            matches = [d for d in self._device_list if d.device_id == kwargs.get('device_id') and d.device_subid == kwargs.get('device_subid')]
            if not matches:
                raise KeyError("Device id/subid {}/{} not found".format(kwargs.get('device_id'), kwargs.get('device_subid')))
            return matches[0]

    def get_topic_list_to_listen(self):
        return ['/'.join([ROOT_TOPIC_NAME, device.device_class, device.device_name, attr_name, 'set']) for device in self._device_list for attr_name in device.get_status_attr_list()]

    @classmethod
    def xor(cls, hexstring_array):
        ints = list(map(lambda x: int(x, 16), hexstring_array))
        return format(reduce(lambda x, y: x ^ y, ints), '02x')

    @classmethod
    def add(cls, hexstring_array):
        ints = list(map(lambda x: int(x, 16), hexstring_array))
        return format(sum(ints) & 0xFF, '02x')

    @classmethod
    def is_valid(cls, payload_hexstring):
        try:
            payload_hexstring = payload_hexstring.lower()
            if not payload_hexstring.startswith('f7'):
                return False
            arr = [payload_hexstring[i:i+2] for i in range(0, len(payload_hexstring), 2)]
            if len(arr) < 6:
                return False
            body = arr[:-2]
            xor_ok = cls.xor(body) == arr[-2]
            add_ok = cls.add(body) == arr[-1]
            return xor_ok and add_ok
        except Exception:
            return False

    def on_raw_message(self, client, userdata, msg):
        # raw payload may contain multiple messages separated by 0xf7
        if msg.topic == ROOT_TOPIC_NAME + '/dev/raw':
            chunks = msg.payload.split(b'\xf7')
            for payload_raw_bytes in chunks[1:]:
                payload_hexstring = 'f7' + payload_raw_bytes.hex()
                try:
                    if not self.is_valid(payload_hexstring):
                        client.publish(ROOT_TOPIC_NAME + '/dev/error', payload_hexstring, qos=1, retain=True)
                        continue

                    pattern = re.compile(r'^f7(?P<device_id>0e|12|32|33|36)(?P<device_subid>[0-9a-f]{2})(?P<message_flag>[0-9a-f]{2})(?:[0-9a-f]{2})(?P<data>[0-9a-f]*?)(?P<xor>[0-9a-f]{2})(?P<add>[0-9a-f]{2})$', re.IGNORECASE)
                    m = pattern.match(payload_hexstring)
                    if not m:
                        client.publish(ROOT_TOPIC_NAME + '/dev/error', payload_hexstring, qos=1, retain=True)
                        continue

                    payload_dict = m.groupdict()
                    try:
                        device = self.get_device(device_id=payload_dict['device_id'], device_subid=payload_dict['device_subid'])
                    except KeyError:
                        client.publish(ROOT_TOPIC_NAME + '/dev/unknown_device', payload_hexstring, qos=1, retain=True)
                        continue

                    parsed = device.parse_payload(payload_dict)
                    for topic, value in parsed.items():
                        client.publish(topic, value, qos=1, retain=False)
                except Exception as e:
                    client.publish(ROOT_TOPIC_NAME + '/dev/error', str(e) + ' | ' + payload_hexstring, qos=1, retain=True)
        else:
            # MQTT -> RS485 command (from homeassistant)
            topic_split = msg.topic.split('/')  # rs485_2mqtt/<class>/<device_name>/<attr>/set
            try:
                if len(topic_split) < 5:
                    client.publish(ROOT_TOPIC_NAME + '/dev/error', 'invalid command topic: ' + msg.topic, qos=1, retain=True)
                    return
                device = self.get_device(device_name=topic_split[2])
                attr_name = topic_split[3]
                payload_decoded = msg.payload.decode()
                payload = device.get_command_payload_byte(attr_name, payload_decoded)
                client.publish(ROOT_TOPIC_NAME + '/dev/command', payload, qos=2, retain=False)
            except Exception as e:
                client.publish(ROOT_TOPIC_NAME + '/dev/error', str(e) + ' | ' + msg.topic + ' | ' + str(msg.payload), qos=1, retain=True)

    def on_disconnect(self, client, userdata, rc):
        raise ConnectionError("MQTT disconnected: rc={}".format(rc))


# instantiate
wallpad = Wallpad()


# ----------------------------
# Helper mappings / utils
# ----------------------------
# Fan speed mapping example (packet -> friendly)
packet_2_payload_percentage = {'01': '약', '02': '중', '03': '강'}
payload_2_packet_percentage = {v: k for k, v in packet_2_payload_percentage.items()}

packet_2_payload_preset = {'01': '바이패스', '04': '자동', '05': '공기청정'}
payload_2_packet_preset = {v: k for k, v in packet_2_payload_preset.items()}


# ----------------------------
# 환풍기 (fan)
# ----------------------------
optional_info_fan = {'optimistic': False, 'speed_range_min': 1, 'speed_range_max': 3}
환풍기 = wallpad.add_device(device_name='환풍기', device_id='32', device_subid='01', device_class='fan', optional_info=optional_info_fan)

# availability (if any packet with flag 01 arrives we mark online)
환풍기.register_status(message_flag='01', attr_name='availability', topic_class='availability_topic', regex=r'()', process_func=lambda v: 'online')

# power: capture single byte representing on/off; regex tuned to find a 01/00 in the data
환풍기.register_status(message_flag='81', attr_name='power', topic_class='state_topic', regex=r'.*?(0[01]).*', process_func=lambda v: 'ON' if v == '01' else 'OFF')
환풍기.register_status(message_flag='c1', attr_name='power', topic_class='state_topic', regex=r'.*?(0[01]).*', process_func=lambda v: 'ON' if v == '01' else 'OFF')

# percentage (speed)
환풍기.register_status(message_flag='81', attr_name='percentage', topic_class='percentage_state_topic', regex=r'.*?(0[1-3]).*', process_func=lambda v: packet_2_payload_percentage.get(v, v))
환풍기.register_status(message_flag='c2', attr_name='percentage', topic_class='percentage_state_topic', regex=r'.*?(0[1-3]).*', process_func=lambda v: packet_2_payload_percentage.get(v, v))

# preset mode
환풍기.register_status(message_flag='43', attr_name='preset_mode', topic_class='preset_mode_state_topic', regex=r'.*?(0[145]).*', process_func=lambda v: packet_2_payload_preset.get(v, v))

# commands
환풍기.register_command(message_flag='41', attr_name='power', topic_class='command_topic', process_func=lambda v: '01' if v == 'ON' else '00')
환풍기.register_command(message_flag='42', attr_name='percentage', topic_class='percentage_command_topic', process_func=lambda v: payload_2_packet_percentage.get(v, '01'))
환풍기.register_command(message_flag='43', attr_name='preset_mode', topic_class='preset_mode_command_topic', process_func=lambda v: payload_2_packet_preset.get(v, '01'))

환풍기.entity_config = {'friendly_name': '환풍기', 'icon': 'mdi:air-filter', 'supported_features': ['percentage', 'preset_mode']}


# ----------------------------
# 가스 차단기 (switch)
# ----------------------------
optional_info_gas = {'optimistic': False}
가스 = wallpad.add_device(device_name='가스', device_id='12', device_subid='01', device_class='switch', optional_info=optional_info_gas)
가스.register_status(message_flag='01', attr_name='availability', topic_class='availability_topic', regex=r'()', process_func=lambda v: 'online')
가스.register_status(message_flag='81', attr_name='power', topic_class='state_topic', regex=r'.*?(0[12]).*', process_func=lambda v: 'ON' if v == '01' else 'OFF')
가스.register_status(message_flag='c1', attr_name='power', topic_class='state_topic', regex=r'.*?(0[12]).*', process_func=lambda v: 'ON' if v == '01' else 'OFF')
가스.register_command(message_flag='41', attr_name='power', topic_class='command_topic', process_func=lambda v: '01' if v == 'ON' else '00')


# ----------------------------
# 조명 (lights) - 여러 개
# ----------------------------
optional_info_light = {'optimistic': False}
거실등1 = wallpad.add_device(device_name='거실등1', device_id='0e', device_subid='11', device_class='light', optional_info=optional_info_light)
거실등2 = wallpad.add_device(device_name='거실등2', device_id='0e', device_subid='12', device_class='light', optional_info=optional_info_light)
간접등  = wallpad.add_device(device_name='간접등',  device_id='0e', device_subid='13', device_class='light', optional_info=optional_info_light)
주방등  = wallpad.add_device(device_name='주방등',  device_id='0e', device_subid='14', device_class='light', optional_info=optional_info_light)
식탁등  = wallpad.add_device(device_name='식탁등',  device_id='0e', device_subid='15', device_class='light', optional_info=optional_info_light)
복도등  = wallpad.add_device(device_name='복도등',  device_id='0e', device_subid='16', device_class='light', optional_info=optional_info_light)
안방등  = wallpad.add_device(device_name='안방등',  device_id='0e', device_subid='21', device_class='light', optional_info=optional_info_light)
대피공간등 = wallpad.add_device(device_name='대피공간등', device_id='0e', device_subid='22', device_class='light', optional_info=optional_info_light)

# 그룹 장치(예: 전체) - child_device로 연결
거실등전체 = wallpad.add_device(device_name='거실등 전체', device_id='0e', device_subid='1f', device_class='light', mqtt_discovery=False, child_device=[거실등1, 거실등2])
안방등전체 = wallpad.add_device(device_name='안방등 전체', device_id='0e', device_subid='2f', device_class='light', mqtt_discovery=False, child_device=[안방등, 대피공간등])

# availability for group
거실등전체.register_status(message_flag='01', attr_name='availability', topic_class='availability_topic', regex=r'()', process_func=lambda v: 'online')
안방등전체.register_status(message_flag='01', attr_name='availability', topic_class='availability_topic', regex=r'()', process_func=lambda v: 'online')

# lights: common status/command handlers
light_power_regex = r'.*?(0[01]).*'  # capture 00/01
for light in [거실등1, 거실등2, 간접등, 주방등, 식탁등, 복도등, 안방등, 대피공간등]:
    light.register_status(message_flag='81', attr_name='power', topic_class='state_topic', regex=light_power_regex, process_func=lambda v: 'ON' if v == '01' else 'OFF')
    light.register_status(message_flag='c1', attr_name='power', topic_class='state_topic', regex=r'.*?(0[01]).*', process_func=lambda v: 'ON' if v == '01' else 'OFF')
    light.register_command(message_flag='41', attr_name='power', topic_class='command_topic', process_func=lambda v: '01' if v == 'ON' else '00')


# ----------------------------
# 난방 (climate) - 간단화된 처리
# ----------------------------
optional_info_climate = {'modes': ['off', 'heat', 'away', 'hotwater'], 'temp_step': 1.0, 'precision': 1.0, 'min_temp': 5.0, 'max_temp': 45.0, 'send_if_off': False}
거실난방 = wallpad.add_device(device_name='거실 난방', device_id='36', device_subid='11', device_class='climate', optional_info=optional_info_climate)
안방난방 = wallpad.add_device(device_name='안방 난방', device_id='36', device_subid='12', device_class='climate', optional_info=optional_info_climate)
확장난방 = wallpad.add_device(device_name='확장 난방', device_id='36', device_subid='13', device_class='climate', optional_info=optional_info_climate)
제인이방난방 = wallpad.add_device(device_name='제인이방 난방', device_id='36', device_subid='14', device_class='climate', optional_info=optional_info_climate)
팬트리난방 = wallpad.add_device(device_name='팬트리 난방', device_id='36', device_subid='15', device_class='climate', optional_info=optional_info_climate)
난방전체 = wallpad.add_device(device_name='난방 전체', device_id='36', device_subid='1f', device_class='climate', mqtt_discovery=False, child_device=[거실난방, 안방난방, 확장난방, 제인이방난방, 팬트리난방])

# availability
난방전체.register_status(message_flag='01', attr_name='availability', topic_class='availability_topic', regex=r'()', process_func=lambda v: 'online')

# For simplicity we capture small hex fields and map them:
def mode_process(v):
    # map sample mode byte to friendly mode (this mapping may need tuning per 실제 패킷)
    m = v.lower()
    if m in ['00', 'ff']:
        return 'off'
    if m == '01':
        return 'heat'
    if m == '02':
        return 'away'
    if m == '03':
        return 'hotwater'
    return 'off'

def temp_process(v):
    # many wallpad packets use a byte representing temperature with fractional bits;
    # here we try to convert a single hex byte to integer degrees as a best-effort.
    try:
        val = int(v, 16)
        # If device uses value/2 format or fixed-point, adjust accordingly. Keep simple:
        if val > 100:
            val = val & 0x7F
        return str(val)
    except:
        return v

# register simple status parsers for multiple message flags
message_flags = ['81', 'c3', 'c4', 'c5', 'c6', 'c7']
for flag in message_flags:
    for dev in [거실난방, 안방난방, 확장난방, 제인이방난방, 팬트리난방]:
        # mode (power)
        dev.register_status(message_flag=flag, attr_name='power', topic_class='mode_state_topic', regex=r'.*?([0-9a-f]{2}).*', process_func=mode_process)
        # away mode (on/off)
        dev.register_status(message_flag=flag, attr_name='away_mode', topic_class='away_mode_state_topic', regex=r'.*?([0-9a-f]{2}).*', process_func=lambda v: 'ON' if v == '01' else 'OFF')
        # target temp
        dev.register_status(message_flag=flag, attr_name='targettemp', topic_class='temperature_state_topic', regex=r'.*?([0-9a-f]{2}).*', process_func=temp_process)
        # current temp
        dev.register_status(message_flag=flag, attr_name='currenttemp', topic_class='current_temperature_topic', regex=r'.*?([0-9a-f]{2}).*', process_func=temp_process)

# commands for climate
난방전체.register_command(message_flag='43', attr_name='power', topic_class='mode_command_topic', process_func=lambda v: '01' if v == 'heat' else '00')
for dev in [거실난방, 안방난방, 확장난방, 제인이방난방, 팬트리난방]:
    dev.register_command(message_flag='43', attr_name='power', topic_class='mode_command_topic', process_func=lambda v: '01' if v == 'heat' else '00')
    # temperature command: convert integer temp to a single hex byte string
    dev.register_command(message_flag='44', attr_name='targettemp', topic_class='temperature_command_topic', process_func=lambda v: format(int(float(v)), '02x'))
    dev.register_command(message_flag='45', attr_name='away_mode', topic_class='away_mode_command_topic', process_func=lambda v: '01' if v == 'ON' else '00')


# ----------------------------
# 엘리베이터 (예시) - 주석으로 남김 (구현 시 필요한 패킷을 확인하세요)
# ----------------------------
# 엘리베이터 패킷 예시는 주석으로 남겨둡니다. 실제로 사용하려면 정확한 message_flag와 payload 형식을 확인해 주세요.
# 엘리베이터 = wallpad.add_device(device_name='엘리베이터', device_id='33', device_subid='01', device_class='switch', optional_info={'optimistic': False})
# 엘리베이터.register_status(message_flag='57', attr_name='power', topic_class='state_topic', regex=r'(00)', process_func=lambda v: 'OFF')
# 엘리베이터.register_status(message_flag='44', attr_name='availability', topic_class='availability_topic', regex=r'(01)', process_func=lambda v: 'online')
# 엘리베이터.register_command(message_flag='81', attr_name='power', topic_class='command_topic', process_func=lambda v: '10' if v == 'ON' else '10')


if __name__ == '__main__':
    wallpad.listen()
