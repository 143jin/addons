import paho.mqtt.client as mqtt
import re
from json import dumps as json_dumps
from functools import reduce
from collections import defaultdict

MQTT_USERNAME = 'eunj'
MQTT_PASSWORD = '!Teatime6699'
MQTT_SERVER = '192.168.200.42'
ROOT_TOPIC_NAME = 'rs485_2mqtt'
HOMEASSISTANT_ROOT_TOPIC_NAME = 'homeassistant'

class Device:
    def __init__(self, device_name, device_id, device_subid, device_class, child_device, mqtt_discovery, optional_info):
        self.device_name = device_name
        self.device_id = device_id
        self.device_subid = device_subid
        self.device_unique_id = 'rs485_' + self.device_id + '_' + self.device_subid
        self.device_class = device_class
        self.child_device = child_device
        self.mqtt_discovery = mqtt_discovery
        self.optional_info = optional_info

        self.__message_flag = {}            # {'power': '41'}
        self.__command_process_func = {}

        self.__status_messages_map = defaultdict(list)
        self.__command_messages_map = {}

    def register_status(self, message_flag, attr_name, regex, topic_class, device_name = None, process_func = lambda v: v):
        device_name = self.device_name if device_name == None else device_name
        self.__status_messages_map[message_flag].append({'regex': regex, 'process_func': process_func, 'device_name': device_name, 'attr_name': attr_name, 'topic_class': topic_class})

    def register_command(self, message_flag, attr_name, topic_class, process_func = lambda v: v):
        self.__command_messages_map[attr_name] = {'message_flag': message_flag, 'attr_name': attr_name, 'topic_class': topic_class, 'process_func': process_func}

    def parse_payload(self, payload_dict):
        result = {}
        device_family = [self] + self.child_device
        for device in device_family:
            for status in device.__status_messages_map[payload_dict['message_flag']]:
                topic = '/'.join([ROOT_TOPIC_NAME, device.device_class, device.device_name, status['attr_name']])
                result[topic] = status['process_func'](re.match(status['regex'], payload_dict['data'])[1])
        return result

    def get_command_payload_byte(self, attr_name, attr_value):  # command('power', 'ON')   command('percentage', 'middle')
        attr_value = self.__command_messages_map[attr_name]['process_func'](attr_value)

        command_payload = ['f7', self.device_id, self.device_subid, self.__command_messages_map[attr_name]['message_flag'], '01', attr_value]
        command_payload.append(Wallpad.xor(command_payload))
        command_payload.append(Wallpad.add(command_payload))
        return bytearray.fromhex(' '.join(command_payload))

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

        for status_list in self.__command_messages_map.values():
            result[status_list['topic_class']] = '/'.join(['~', status_list['attr_name'], 'set'])

        result['device'] = {
            'identifiers': self.device_unique_id,
            'name': self.device_name
        }
        return json_dumps(result, ensure_ascii = False)

    def get_status_attr_list(self):
        return list(set([status['attr_name'] for status_list in self.__status_messages_map.values() for status in status_list]))

class Wallpad:
    _device_list = []

    def __init__(self):
        self.mqtt_client = mqtt.Client()
        self.mqtt_client.on_message    = self.on_raw_message
        self.mqtt_client.on_disconnect = self.on_disconnect
        self.mqtt_client.username_pw_set(username=MQTT_USERNAME, password=MQTT_PASSWORD)
        self.mqtt_client.connect(MQTT_SERVER, 1883)

    def listen(self):
        self.register_mqtt_discovery()
        self.mqtt_client.subscribe([(topic, 2) for topic in [ROOT_TOPIC_NAME + '/dev/raw'] + self.get_topic_list_to_listen()])
        self.mqtt_client.loop_forever()

    def register_mqtt_discovery(self):
        for device in self._device_list:
            if device.mqtt_discovery:
                topic = '/'.join([HOMEASSISTANT_ROOT_TOPIC_NAME, device.device_class, device.device_unique_id, 'config'])
                payload = device.get_mqtt_discovery_payload()
                self.mqtt_client.publish(topic, payload, qos = 2, retain = True)

    def add_device(self, device_name, device_id, device_subid, device_class, child_device = [], mqtt_discovery = True, optional_info = {}):
        device = Device(device_name, device_id, device_subid, device_class, child_device, mqtt_discovery, optional_info)
        self._device_list.append(device)
        return device

    def get_device(self, **kwargs):
        if 'device_name' in kwargs:
            return [device for device in self._device_list if device.device_name == kwargs['device_name']][0]
        else:
            return [device for device in self._device_list if device.device_id == kwargs['device_id'] and device.device_subid == kwargs['device_subid']][0]

    def get_topic_list_to_listen(self):
        return ['/'.join([ROOT_TOPIC_NAME, device.device_class, device.device_name, attr_name, 'set']) for device in self._device_list for attr_name in device.get_status_attr_list()]

    @classmethod
    def xor(cls, hexstring_array):
        return format(reduce((lambda x, y: x^y), list(map(lambda x: int(x, 16), hexstring_array))), '02x')

    @classmethod
    def add(cls, hexstring_array): # hexstring_array ['f7', '32', ...]
        return format(reduce((lambda x, y: x+y), list(map(lambda x: int(x, 16), hexstring_array))), '02x')[-2:]

    @classmethod
    def is_valid(cls, payload_hexstring):
        payload_hexstring_array = [payload_hexstring[i:i+2] for i in range(0, len(payload_hexstring), 2)] # ['f7', '0e', '1f', '81', '04', '00', '00', '00', '00', '63', '0c']
        try:
            result = int(payload_hexstring_array[4], 16) + 7 == len(payload_hexstring_array) and cls.xor(payload_hexstring_array[:-2]) == payload_hexstring_array[-2:-1][0] and cls.add(payload_hexstring_array[:-1]) == payload_hexstring_array[-1:][0]
            return result
        except:
            return False

    def on_raw_message(self, client, userdata, msg):
        if msg.topic == ROOT_TOPIC_NAME + '/dev/raw': # ew11이 MQTT에 rs485 패킷을 publish하는 경우
            for payload_raw_bytes in msg.payload.split(b'\xf7')[1:]: # payload 내에 여러 메시지가 있는 경우, \f7 disappear as delimiter here
                payload_hexstring = 'f7' + payload_raw_bytes.hex() # 'f7361f810f000001000017179817981717969896de22'
                try:
                    if self.is_valid(payload_hexstring):
                        payload_dict = re.match(r'f7(?P<device_id>0e|12|32|33|36)(?P<device_subid>[0-9a-f]{2})(?P<message_flag>[0-9a-f]{2})(?:[0-9a-f]{2})(?P<data>[0-9a-f]*)(?P<xor>[0-9a-f]{2})(?P<add>[0-9a-f]{2})', payload_hexstring).groupdict()

                        for topic, value in self.get_device(device_id = payload_dict['device_id'], device_subid = payload_dict['device_subid']).parse_payload(payload_dict).items():
                            client.publish(topic, value, qos = 1, retain = False)
                    else:
                        continue
                except Exception as e:
                    client.publish(ROOT_TOPIC_NAME + '/dev/error', payload_hexstring, qos = 1, retain = True)

        else: # homeassistant에서 명령하여 MQTT topic을 publish하는 경우
            topic_split = msg.topic.split('/') # rs485_2mqtt/light/안방등/power/set
            device = self.get_device(device_name = topic_split[2])
            payload = device.get_command_payload_byte(topic_split[3], msg.payload.decode())
            client.publish(ROOT_TOPIC_NAME + '/dev/command', payload, qos = 2, retain = False)

    def on_disconnect(self, client, userdata, rc):
        raise ConnectionError

MQTT_SERVER = '192.168.200.42'
ROOT_TOPIC_NAME = 'rs485_2mqtt'
HOMEASSISTANT_ROOT_TOPIC_NAME = 'homeassistant'
wallpad = Wallpad()

packet_2_payload_percentage = {'00': '0', '01': '1', '02': '2', '03': '3'}
packet_2_payload_oscillation = {'03': 'oscillate_on', '00': 'oscillation_off', '01': 'oscillate_off'}

### 환풍기 ###
optional_info = {'optimistic': 'false', 'speed_range_min': 1, 'speed_range_max': 3}
환풍기 = wallpad.add_device(device_name = '환풍기', device_id = '32', device_subid = '01', device_class = 'fan', optional_info = optional_info)
환풍기.register_status(message_flag = '01', attr_name = 'availability', topic_class ='availability_topic',      regex = r'()', process_func = lambda v: 'online')
환풍기.register_status(message_flag = '81', attr_name = 'power',        topic_class ='state_topic',             regex = r'00(0[01])0[0-3]0[013]00', process_func = lambda v: 'ON' if v == '01' else 'OFF')
환풍기.register_status(message_flag = 'c1', attr_name = 'power',        topic_class ='state_topic',             regex = r'00(0[01])0[0-3]0[013]00', process_func = lambda v: 'ON' if v == '01' else 'OFF')
환풍기.register_status(message_flag = '81', attr_name = 'percentage',   topic_class ='percentage_state_topic',  regex = r'000[01](0[0-3])0[013]00', process_func = lambda v: packet_2_payload_percentage[v])
환풍기.register_status(message_flag = 'c2', attr_name = 'percentage',   topic_class ='percentage_state_topic',  regex = r'000[01](0[0-3])0[013]00', process_func = lambda v: packet_2_payload_percentage[v])
환풍기.register_status(message_flag = '81', attr_name = 'heat',         topic_class ='oscillation_state_topic', regex = r'000[01]0[0-3](0[013])00', process_func = lambda v: packet_2_payload_oscillation[v])
환풍기.register_status(message_flag = 'c3', attr_name = 'heat',         topic_class ='oscillation_state_topic', regex = r'000[01]0[0-3](0[013])00', process_func = lambda v: packet_2_payload_oscillation[v])

환풍기.register_command(message_flag = '41', attr_name = 'power',       topic_class = 'command_topic', process_func = lambda v: '01' if v =='ON' else '00')
환풍기.register_command(message_flag = '42', attr_name = 'percentage',  topic_class = 'percentage_command_topic', process_func = lambda v: {payload: packet for packet, payload in packet_2_payload_percentage.items()}[v])
환풍기.register_command(message_flag = '43', attr_name = 'heat',        topic_class = 'oscillation_command_topic', process_func = lambda v: {payload: packet for packet, payload in packet_2_payload_oscillation.items()}[v])

### 가스차단기 ###
optional_info = {'optimistic': 'false'}
가스 = wallpad.add_device(device_name = '가스', device_id = '12', device_subid = '01', device_class = 'switch', optional_info = optional_info)
가스.register_status(message_flag = '01', attr_name = 'availability', topic_class ='availability_topic', regex = r'()', process_func = lambda v: 'online')
가스.register_status(message_flag = '81', attr_name = 'power', topic_class ='state_topic', regex = r'00(0[12])', process_func = lambda v: 'ON' if v == '01' else 'OFF')
가스.register_status(message_flag = 'c1', attr_name = 'power', topic_class ='state_topic', regex = r'00(0[12])', process_func = lambda v: 'ON' if v == '01' else 'OFF')

가스.register_command(message_flag = '41', attr_name = 'power', topic_class = 'command_topic', process_func = lambda v: '01' if v == 'ON' else '00')

### 조명 ###
optional_info = {'optimistic': 'false'}
거실등1    = wallpad.add_device(device_name = '거실등1', device_id = '0e', device_subid = '11', device_class = 'light', optional_info = optional_info)
거실등2    = wallpad.add_device(device_name = '거실등2', device_id = '0e', device_subid = '12', device_class = 'light', optional_info = optional_info)
간접등     = wallpad.add_device(device_name = '간접등',  device_id = '0e', device_subid = '13', device_class = 'light', optional_info = optional_info)
주방등     = wallpad.add_device(device_name = '주방등',  device_id = '0e', device_subid = '14', device_class = 'light', optional_info = optional_info)
식탁등     = wallpad.add_device(device_name = '식탁등',  device_id = '0e', device_subid = '15', device_class = 'light', optional_info = optional_info)
복도등     = wallpad.add_device(device_name = '복도등',  device_id = '0e', device_subid = '16', device_class = 'light', optional_info = optional_info)
안방등     = wallpad.add_device(device_name = '안방등',  device_id = '0e', device_subid = '21', device_class = 'light', optional_info = optional_info)
대피공간등     = wallpad.add_device(device_name = '대피공간등',  device_id = '0e', device_subid = '22', device_class = 'light', optional_info = optional_info)
거실등전체 = wallpad.add_device(device_name = '거실등 전체', device_id = '0e', device_subid = '1f', device_class = 'light', mqtt_discovery = False, child_device = [거실등1, 거실등2, 간접등, 주방등, 식탁등, 복도등])
안방등전체 = wallpad.add_device(device_name = '안방등 전체', device_id = '0e', device_subid = '2f', device_class = 'light', mqtt_discovery = False, child_device = [안방등, 대피공간등])

거실등전체.register_status(message_flag = '01', attr_name = 'availability', topic_class ='availability_topic', regex = r'()', process_func = lambda v: 'online')
안방등전체.register_status(message_flag = '01', attr_name = 'availability', topic_class ='availability_topic', regex = r'()', process_func = lambda v: 'online')

거실등1.register_status(message_flag = '81', attr_name = 'power', topic_class ='state_topic', regex = r'00(0[01])0[01]0[01]', process_func = lambda v: 'ON' if v == '01' else 'OFF')
거실등2.register_status(message_flag = '81', attr_name = 'power', topic_class ='state_topic', regex = r'000[01](0[01])0[01]', process_func = lambda v: 'ON' if v == '01' else 'OFF')
간접등.register_status(message_flag = '81', attr_name = 'power', topic_class ='state_topic', regex = r'000[01]0[01](0[01])0[01]', process_func = lambda v: 'ON' if v == '01' else 'OFF')
주방등.register_status(message_flag = '81', attr_name = 'power', topic_class ='state_topic', regex = r'000[01]0[01]0[01](0[01])', process_func = lambda v: 'ON' if v == '01' else 'OFF')
식탁등.register_status(message_flag = '81', attr_name = 'power', topic_class ='state_topic', regex = r'000[01]0[01]0[01]0[01](0[01])', process_func = lambda v: 'ON' if v == '01' else 'OFF')
복도등.register_status(message_flag = '81', attr_name = 'power', topic_class ='state_topic', regex = r'000[01]0[01]0[01]0[01]0[01](0[01])', process_func = lambda v: 'ON' if v == '01' else 'OFF')
안방등.register_status(message_flag = '81', attr_name = 'power', topic_class ='state_topic', regex = r'000[01]0[01]0[01]0[01]0[01]0[01](0[01])', process_func = lambda v: 'ON' if v == '01' else 'OFF')
대피공간등.register_status(message_flag = '81', attr_name = 'power', topic_class ='state_topic', regex = r'000[01]0[01]0[01]0[01]0[01]0[01]0[01](0[01])', process_func = lambda v: 'ON' if v == '01' else 'OFF')

거실등1.register_status(message_flag = 'c1', attr_name = 'power', topic_class ='state_topic', regex = r'00(0[01])', process_func = lambda v: 'ON' if v == '01' else 'OFF')
거실등2.register_status(message_flag = 'c1', attr_name = 'power', topic_class ='state_topic', regex = r'00(0[01])', process_func = lambda v: 'ON' if v == '01' else 'OFF')
간접등.register_status(message_flag = 'c1', attr_name = 'power', topic_class ='state_topic', regex = r'00(0[01])', process_func = lambda v: 'ON' if v == '01' else 'OFF')
주방등.register_status(message_flag = 'c1', attr_name = 'power', topic_class ='state_topic', regex = r'00(0[01])', process_func = lambda v: 'ON' if v == '01' else 'OFF')
식탁등.register_status(message_flag = 'c1', attr_name = 'power', topic_class ='state_topic', regex = r'00(0[01])', process_func = lambda v: 'ON' if v == '01' else 'OFF')
복도등.register_status(message_flag = 'c1', attr_name = 'power', topic_class ='state_topic', regex = r'00(0[01])', process_func = lambda v: 'ON' if v == '01' else 'OFF')
안방등.register_status(message_flag = 'c1', attr_name = 'power', topic_class ='state_topic', regex = r'00(0[01])', process_func = lambda v: 'ON' if v == '01' else 'OFF')
대피공간등.register_status(message_flag = 'c1', attr_name = 'power', topic_class ='state_topic', regex = r'00(0[01])', process_func = lambda v: 'ON' if v == '01' else 'OFF')

거실등1.register_command(message_flag = '41', attr_name = 'power', topic_class = 'command_topic', process_func = lambda v: '01' if v =='ON' else '00') # 'ON': '01' / 'OFF': '00'
거실등2.register_command(message_flag = '41', attr_name = 'power', topic_class = 'command_topic', process_func = lambda v: '01' if v =='ON' else '00')
간접등.register_command(message_flag = '41', attr_name = 'power', topic_class = 'command_topic', process_func = lambda v: '01' if v =='ON' else '00')
주방등.register_command(message_flag = '41', attr_name = 'power', topic_class = 'command_topic', process_func = lambda v: '01' if v =='ON' else '00')
식탁등.register_command(message_flag = '41', attr_name = 'power', topic_class = 'command_topic', process_func = lambda v: '01' if v =='ON' else '00')
복도등.register_command(message_flag = '41', attr_name = 'power', topic_class = 'command_topic', process_func = lambda v: '01' if v =='ON' else '00')
안방등.register_command(message_flag = '41', attr_name = 'power', topic_class = 'command_topic', process_func = lambda v: '01' if v =='ON' else '00')
대피공간등.register_command(message_flag = '41', attr_name = 'power', topic_class = 'command_topic', process_func = lambda v: '01' if v =='ON' else '00')

### 난방 ###
optional_info = {'modes': ['off', 'heat'], 'temp_step': 1.0, 'precision': 1.0, 'min_temp': 5.0, 'max_temp': 45.0, 'send_if_off': 'false'}
거실난방 =  wallpad.add_device(device_name = '거실 난방',   device_id = '36', device_subid = '11', device_class = 'climate', optional_info = optional_info)
안방난방 =  wallpad.add_device(device_name = '안방 난방',   device_id = '36', device_subid = '12', device_class = 'climate', optional_info = optional_info)
확장난방 =  wallpad.add_device(device_name = '확장 난방',   device_id = '36', device_subid = '13', device_class = 'climate', optional_info = optional_info)
제인이방난방 =  wallpad.add_device(device_name = '제인이방 난방',   device_id = '36', device_subid = '14', device_class = 'climate', optional_info = optional_info)
팬트리난방= wallpad.add_device(device_name = '팬트리 난방', device_id = '36', device_subid = '15', device_class = 'climate', optional_info = optional_info)
난방전체 =  wallpad.add_device(device_name = '난방 전체',   device_id = '36', device_subid = '1f', device_class = 'climate', mqtt_discovery = False, child_device = [거실난방, 안방난방, 확장난방, 제인이방난방, 팬트리난방])

난방전체.register_status(message_flag = '01', attr_name = 'availability', regex = r'()', topic_class ='availability_topic', process_func = lambda v: 'online')

for message_flag in ['81', 'c3', 'c4', 'c5']:
    거실난방.register_status(  message_flag = message_flag, attr_name = 'power', topic_class = 'mode_state_topic', regex = r'00([\da-fA-F]{2})[\da-fA-F]{2}[\da-fA-F]{4}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}', process_func = lambda v: 'heat' if format(int(v, 16), '05b')[0] == '1' else 'off')
    안방난방.register_status(  message_flag = message_flag, attr_name = 'power', topic_class = 'mode_state_topic', regex = r'00([\da-fA-F]{2})[\da-fA-F]{2}[\da-fA-F]{4}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}', process_func = lambda v: 'heat' if format(int(v, 16), '05b')[1] == '1' else 'off')
    확장난방.register_status(  message_flag = message_flag, attr_name = 'power', topic_class = 'mode_state_topic', regex = r'00([\da-fA-F]{2})[\da-fA-F]{2}[\da-fA-F]{4}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}', process_func = lambda v: 'heat' if format(int(v, 16), '05b')[2] == '1' else 'off')
    제인이방난방.register_status(  message_flag = message_flag, attr_name = 'power', topic_class = 'mode_state_topic', regex = r'00([\da-fA-F]{2})[\da-fA-F]{2}[\da-fA-F]{4}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}', process_func = lambda v: 'heat' if format(int(v, 16), '05b')[3] == '1' else 'off')
    팬트리난방.register_status(message_flag = message_flag, attr_name = 'power', topic_class = 'mode_state_topic', regex = r'00([\da-fA-F]{2})[\da-fA-F]{2}[\da-fA-F]{4}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}', process_func = lambda v: 'heat' if format(int(v, 16), '05b')[4] == '1' else 'off')

    거실난방.register_status(  message_flag = message_flag, attr_name = 'away_mode', topic_class = 'away_mode_state_topic', regex = r'00[\da-fA-F]{2}([\da-fA-F]{2})[\da-fA-F]{4}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}', process_func = lambda v: 'ON' if format(int(v, 16), '05b')[0] == '1' else 'OFF')
    안방난방.register_status(  message_flag = message_flag, attr_name = 'away_mode', topic_class = 'away_mode_state_topic', regex = r'00[\da-fA-F]{2}([\da-fA-F]{2})[\da-fA-F]{4}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}', process_func = lambda v: 'ON' if format(int(v, 16), '05b')[1] == '1' else 'OFF')
    확장난방.register_status(  message_flag = message_flag, attr_name = 'away_mode', topic_class = 'away_mode_state_topic', regex = r'00[\da-fA-F]{2}([\da-fA-F]{2})[\da-fA-F]{4}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}', process_func = lambda v: 'ON' if format(int(v, 16), '05b')[2] == '1' else 'OFF')
    제인이방난방.register_status(  message_flag = message_flag, attr_name = 'away_mode', topic_class = 'away_mode_state_topic', regex = r'00[\da-fA-F]{2}([\da-fA-F]{2})[\da-fA-F]{4}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}', process_func = lambda v: 'ON' if format(int(v, 16), '05b')[3] == '1' else 'OFF')
    팬트리난방.register_status(message_flag = message_flag, attr_name = 'away_mode', topic_class = 'away_mode_state_topic', regex = r'00[\da-fA-F]{2}([\da-fA-F]{2})[\da-fA-F]{4}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}', process_func = lambda v: 'ON' if format(int(v, 16), '05b')[4] == '1' else 'OFF')

    거실난방.register_status(  message_flag = message_flag, attr_name = 'targettemp',  topic_class ='temperature_state_topic',   regex = r'00[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{4}([\da-fA-F]{2})[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}', process_func = lambda v: int(v, 16) % 128 + int(v, 16) // 128 * 0.5)
    안방난방.register_status(  message_flag = message_flag, attr_name = 'targettemp',  topic_class ='temperature_state_topic',   regex = r'00[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{4}[\da-fA-F]{2}[\da-fA-F]{2}([\da-fA-F]{2})[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}', process_func = lambda v: int(v, 16) % 128 + int(v, 16) // 128 * 0.5)
    확장난방.register_status(  message_flag = message_flag, attr_name = 'targettemp',  topic_class ='temperature_state_topic',   regex = r'00[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{4}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}([\da-fA-F]{2})[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}', process_func = lambda v: int(v, 16) % 128 + int(v, 16) // 128 * 0.5)
    제인이방난방.register_status(  message_flag = message_flag, attr_name = 'targettemp',  topic_class ='temperature_state_topic',   regex = r'00[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{4}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}([\da-fA-F]{2})[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}', process_func = lambda v: int(v, 16) % 128 + int(v, 16) // 128 * 0.5)
    팬트리난방.register_status(message_flag = message_flag, attr_name = 'targettemp',  topic_class ='temperature_state_topic',   regex = r'00[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{4}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}([\da-fA-F]{2})[\da-fA-F]{2}', process_func = lambda v: int(v, 16) % 128 + int(v, 16) // 128 * 0.5)

    거실난방.register_status(  message_flag = message_flag, attr_name = 'currenttemp', topic_class ='current_temperature_topic', regex = r'00[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{4}[\da-fA-F]{2}([\da-fA-F]{2})[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}', process_func = lambda v: int(v, 16) % 128 + int(v, 16) // 128 * 0.5)
    안방난방.register_status(  message_flag = message_flag, attr_name = 'currenttemp', topic_class ='current_temperature_topic', regex = r'00[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{4}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}([\da-fA-F]{2})[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}', process_func = lambda v: int(v, 16) % 128 + int(v, 16) // 128 * 0.5)
    확장난방.register_status(  message_flag = message_flag, attr_name = 'currenttemp', topic_class ='current_temperature_topic', regex = r'00[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{4}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}([\da-fA-F]{2})[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}', process_func = lambda v: int(v, 16) % 128 + int(v, 16) // 128 * 0.5)
    제인이방난방.register_status(  message_flag = message_flag, attr_name = 'currenttemp', topic_class ='current_temperature_topic', regex = r'00[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{4}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}([\da-fA-F]{2})[\da-fA-F]{2}[\da-fA-F]{2}', process_func = lambda v: int(v, 16) % 128 + int(v, 16) // 128 * 0.5)
    팬트리난방.register_status(message_flag = message_flag, attr_name = 'currenttemp', topic_class ='current_temperature_topic', regex = r'00[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{4}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}[\da-fA-F]{2}([\da-fA-F]{2})', process_func = lambda v: int(v, 16) % 128 + int(v, 16) // 128 * 0.5)

난방전체.register_command(message_flag = '43', attr_name = 'power', topic_class = 'mode_command_topic', process_func = lambda v: '01' if v == 'heat' else '00')

거실난방.register_command(message_flag = '43', attr_name = 'power', topic_class = 'mode_command_topic', process_func = lambda v: '01' if v == 'heat' else '00')
거실난방.register_command(message_flag = '44', attr_name = 'targettemp', topic_class = 'temperature_command_topic', process_func = lambda v: format(int(float(v) // 1 + float(v) % 1 * 128 * 2), '02x'))
거실난방.register_command(message_flag = '45', attr_name = 'away_mode', topic_class = 'away_mode_command_topic', process_func = lambda v: '01' if v =='ON' else '00')

안방난방.register_command(message_flag = '43', attr_name = 'power', topic_class = 'mode_command_topic', process_func = lambda v: '01' if v == 'heat' else '00')
안방난방.register_command(message_flag = '44', attr_name = 'targettemp', topic_class = 'temperature_command_topic', process_func = lambda v: format(int(float(v) // 1 + float(v) % 1 * 128 * 2), '02x'))
안방난방.register_command(message_flag = '45', attr_name = 'away_mode', topic_class = 'away_mode_command_topic', process_func = lambda v: '01' if v =='ON' else '00')

확장난방.register_command(message_flag = '43', attr_name = 'power', topic_class = 'mode_command_topic', process_func = lambda v: '01' if v == 'heat' else '00')
확장난방.register_command(message_flag = '44', attr_name = 'targettemp', topic_class = 'temperature_command_topic', process_func = lambda v: format(int(float(v) // 1 + float(v) % 1 * 128 * 2), '02x'))
확장난방.register_command(message_flag = '45', attr_name = 'away_mode', topic_class = 'away_mode_command_topic', process_func = lambda v: '01' if v =='ON' else '00')

제인이방난방.register_command(message_flag = '43', attr_name = 'power', topic_class = 'mode_command_topic', process_func = lambda v: '01' if v == 'heat' else '00') # { 'ON': '01', 'OFF': '00' }
제인이방난방.register_command(message_flag = '44', attr_name = 'targettemp', topic_class = 'temperature_command_topic', process_func = lambda v: format(int(float(v) // 1 + float(v) % 1 * 128 * 2), '02x'))
제인이방난방.register_command(message_flag = '45', attr_name = 'away_mode', topic_class = 'away_mode_command_topic', process_func = lambda v: '01' if v =='ON' else '00')

팬트리난방.register_command(message_flag = '43', attr_name = 'power', topic_class = 'mode_command_topic', process_func = lambda v: '01' if v == 'heat' else '00') # , { 'ON': '01', 'OFF': '00' }
팬트리난방.register_command(message_flag = '44', attr_name = 'targettemp', topic_class = 'temperature_command_topic', process_func = lambda v: format(int(float(v) // 1 + float(v) % 1 * 128 * 2), '02x'))
팬트리난방.register_command(message_flag = '45', attr_name = 'away_mode', topic_class = 'away_mode_command_topic', process_func = lambda v: '01' if v =='ON' else '00')

# 엘리베이터 호출 버튼 생성
for message_flag in ['33', '44', '81', '57']:
엘리베이터 = wallpad.add_device(device_name='엘리베이터', device_id='33', device_subid='01', device_class='button') #스위치 대신 버튼 사용

# 층수 패킷 수신 및 상태 업데이트
엘리베이터.register_status(message_flag = '44', attr_name='floor', topic_class='state_topic', regex=r'01([0-9A-F]{2})[0-9A-F]{2}[0-9A-F]{2}', process_func=lambda v: -1 if v == 'F1' else (-2 if v == 'F2' else int(v, 10)))

# 엘리베이터 호출 버튼 클릭 시 호출 패킷 전송
def call_elevator(_):
    return bytes.fromhex("F7330181030024006336")  # 호출 패킷

엘리베이터.register_command(message_flag='81', attr_name='press', topic_class='command_topic', process_func=call_elevator)

# 도착 패킷 수신 시 알림 처리
def elevator_arrived(_):
    엘리베이터.set_state('current_floor', 'Arrived')
    return "Arrived"

엘리베이터.register_status(message_flag='57', attr_name='arrival_status', topic_class='state_topic', regex=r'F7 33 01 57 00 92 14', process_func=elevator_arrived)

wallpad.listen()
