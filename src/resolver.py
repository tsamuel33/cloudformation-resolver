import argparse
import base64
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import subprocess
import sys

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from jsonpath_ng.jsonpath import Fields
from jsonpath_ng.ext import parse
import yaml

# Set up logger
logging.basicConfig(stream=sys.stderr, level=logging.INFO, format='[%(asctime)s] %(levelname)s %(name)s@%(lineno)d: %(message)s')
logger = logging.getLogger(Path(__file__).name)

# Arguments
parser = argparse.ArgumentParser(description='Accept AWS parameters')
parser.add_argument('--template', type=str, help='Name of the template file', required=True)
parser.add_argument('--parameters', type=str, help='Name of the parameter file', required=False)
args = vars(parser.parse_args())

# Instrisic function classes
class Ref(object):
    """YAML representation of the '!Ref' intrinsic function"""
    def __init__(self, data):
        self.data = data

class Sub(object):
    """YAML representation of the '!Sub' intrinsic function"""
    def __init__(self, data):
        self.data = data

class Split(object):
    """YAML representation of the '!Split' intrinsic function"""
    def __init__(self, data):
        self.data = data

class Select(object):
    """YAML representation of the '!Select' intrinsic function"""
    def __init__(self, data):
        self.data = data

class Join(object):
    """YAML representation of the '!Join' intrinsic function"""
    def __init__(self, data):
        self.data = data

class ImportValue(object):
    """YAML representation of the '!ImportValue' intrinsic function"""
    def __init__(self, data):
        self.data = data

class GetAZs(object):
    """YAML representation of the '!GetAZs' intrinsic function"""
    def __init__(self, data):
        self.data = data

class GetAtt(object):
    """YAML representation of the '!GetAtt' intrinsic function"""
    def __init__(self, data):
        self.data = data

class FindInMap(object):
    """YAML representation of the '!FindInMap' intrinsic function"""
    def __init__(self, data):
        self.data = data

class Cidr(object):
    """YAML representation of the '!Cidr' intrinsic function"""
    def __init__(self, data):
        self.data = data

class Base64(object):
    """YAML representation of the '!Base64' intrinsic function"""
    def __init__(self, data):
        self.data = data
    
class And(object):
    """YAML representation of the '!And' condition function"""
    def __init__(self, data):
        self.data = data

class Equals(object):
    """YAML representation of the '!Equals' condition function"""
    def __init__(self, data):
        self.data = data

class If(object):
    """YAML representation of the '!If' condition function"""
    def __init__(self, data):
        self.data = data

class Not(object):
    """YAML representation of the '!Not' condition function"""
    def __init__(self, data):
        self.data = data

class Or(object):
    """YAML representation of the '!Or' condition function"""
    def __init__(self, data):
        self.data = data

class Condition(object):
    """YAML representation of the '!Condition' condition function"""
    def __init__(self, data):
        self.data = data

# Intrisnsic function constructor
def yaml_constructor(loader, node):
    if isinstance(node, (yaml.nodes.SequenceNode)):
        value = loader.construct_sequence(node)
    elif isinstance(node, (yaml.nodes.MappingNode)):
        value = loader.construct_mapping(node)
    elif isinstance(node, (yaml.nodes.ScalarNode)):
        value = loader.construct_scalar(node)
    class_name = node.tag.lstrip("!")
    class_obj = getattr(sys.modules[__name__], class_name)
    if class_name == "GetAtt":
        return { "Fn::GetAtt" : class_obj(value).data.split(".") }
    elif class_name in ["Ref", "Condition"]:
        return { class_name : class_obj(value).data }
    else:
        return { "::".join(("Fn", class_name)) : class_obj(value).data }

def add_yaml_constructor(tag):
    yaml.add_constructor(tag, yaml_constructor, yaml.SafeLoader)

# Add constructors to YAML loader
tags = [
    u'!Ref',
    u'!Sub',
    u'!Split',
    u'!Select',
    u'!Join',
    u'!ImportValue',
    u'!GetAZs',
    u'!GetAtt',
    u'!FindInMap',
    u'!Cidr',
    u'!Base64',
    u'!And',
    u'!Equals',
    u'!If',
    u'!Not',
    u'!Or',
    u'!Condition'
]
for tag in tags:
    add_yaml_constructor(tag)

def create_test_file(stack_name, data):
    # home_dir = Path(os.environ['HOME'])
    home_dir = Path(__file__).parents[1]
    validation_dir = home_dir / "rendered_templates"
    rendered_path = validation_dir / ".".join((stack_name, "json"))
    if not validation_dir.exists():
        os.mkdir(validation_dir, mode=760)
    # if rendered_path.exists():
    #     original_path = rendered_path
    #     parent = rendered_path.parent
    #     stem = rendered_path.stem
    #     rendered_path = parent / "".join((stem, "_1", ".json"))
    #     message = "Test file {} ".format(original_path.as_posix()) + \
    #         "already exists. There may be conflicting templates " + \
    #         "for stack: {}. Creating".format(stack_name) + \
    #         " new file: {}".format(stack_name,rendered_path.as_posix())
    #     logger.warning(message)
    with open(rendered_path, "w") as file:
        file.write(data)
        logger.info("Created test file: {}".format(rendered_path.as_posix()))
        file.close()
    return rendered_path

def convert_to_json(data_path):
    with open(data_path, 'r') as template_file:
        template_data = template_file.read()
    if data_path.suffix in [".template", ".yaml", ".yml"]:
        data_object = yaml.safe_load(template_data)
    elif data_path.suffix == ".json":
        data_object = json.loads(template_data)
    template_file.close()
    json_object = json.dumps(data_object, indent=2, default=str)
    json_data = json.loads(json_object)
    return json_data

def parse_parameters(parameter_list):
    if parameter_list is None:
        parameters = None
    else:
        parameters = dict((param['ParameterKey'], param['ParameterValue']) for param in parameter_list)
    return parameters

def get_param_value(parameters, param_key):
    if parameters is not None:
        try:
            output = parameters[param_key]
        except KeyError:
            output = None
    elif parameters is None:
        output = None
    return output

def check_int(input):
    try:
        int(input)
        return True
    except ValueError:
        return False

# JSONPath is unable to find a path that has ":" in it (i.e, Fn::Sub).
# Add quotations to the field name for the search to work.
def clean_location(location):
    output = '$'
    parts = location.split(".")
    for part in parts:
        if ":" in part or check_int(part):
            output = output + "." + '"{}"'.format(part)
        else:
            output = output + "." + part
    return output

def process_template(location, data, parameters, region, partition, account_number, stack_name, az_list, cf_exports):
    parsed_location = parse_location(location)
    loc = parsed_location[0]
    action = parsed_location[1]
    safe_loc = clean_location(loc)
    safe_path = parse(safe_loc)
    current = parse(clean_location(location)).find(data)[0].value
    if action == "Ref":
        replace_ref(safe_path, data, parameters, current, region, partition, account_number, stack_name)
    elif action == "Fn::Sub":
        replace_sub(safe_path, data, parameters, current, region, partition, account_number, stack_name)
    elif action == "Fn::Split":
        replace_split(safe_path, data, current)
    elif action == "Fn::Select":
        replace_select(safe_path, data, current)
    elif action == "Fn::Join":
        replace_join(safe_path, data, current)
    elif action == "Fn::FindInMap":
        replace_findinmap(safe_path, data, current)
    elif action == "Fn::Base64":
        replace_base64(safe_path, data, current)
    elif action == "Fn::Equals":
        replace_equals(safe_path, data, current)
    elif action == "Fn::Not":
        replace_not(safe_path, data, current)
    elif action == "Fn::And":
        replace_and(safe_path, data, current)
    elif action == "Fn::Or":
        replace_or(safe_path, data, current)
    elif action == "Condition":
        replace_condition(safe_path, data, current)
    elif action == "Fn::If":
        replace_if(safe_path, data, current)
    elif action == "Fn::Cidr":
        replace_cidr(safe_path, data, current)
    elif action == "Fn::GetAZs":
        replace_getazs(safe_path, data, az_list)
    elif action == "Fn::ImportValue":
        replace_importvalue(safe_path, data, current, cf_exports)

def get_ref_value(parameters, param_key, region, partition, account_number, stack_name):
    if param_key == "AWS::Region":
        value = region
    elif param_key == "AWS::AccountId":
        value = account_number
    elif param_key == "AWS::Partition":
        value = partition
    elif param_key == "AWS::StackName":
        value = stack_name
    elif param_key == "AWS::StackId":
        prefix = ":".join(('arn', partition, 'cloudformation', region, account_number, 'stack'))
        value = "/".join((prefix, stack_name, 'placehol-der0-1234-5678-90abcdefghij'))
    elif param_key == "AWS::URLSuffix":
        if partition == "aws-cn":
            value = "amazonaws.com.cn"
        else:
            value = "amazonaws.com"
    else:
        value = get_param_value(parameters, param_key)
    return value

def replace_ref(json_path, data, parameters, param_key, region, partition, account_number, stack_name):
    value = get_ref_value(parameters, param_key, region, partition, account_number, stack_name)
    if value is not None:
        json_path.update(data, value)

def replace_split(json_path, data, input):
    proceed = False
    if isinstance(input[0], str) and isinstance(input[1], str):
        proceed = True
    if proceed:
        delimiter = input[0]
        input_string = input[1]
        value = input_string.split(str(delimiter))
        json_path.update(data, value)

def replace_select(json_path, data, input):
    proceed = False
    if isinstance(input[0], int) and isinstance(input[1], list):
        proceed = True
    if proceed:
        index = input[0]
        input_list = input[1]
        value = input_list[index]
        json_path.update(data, value)

def replace_join(json_path, data, input):
    proceed = False
    if isinstance(input[0], str) and isinstance(input[1], list):
        proceed = True
    if proceed:
        delimiter = input[0]
        input_list = input[1]
        value = delimiter.join(input_list)
        json_path.update(data, value)

def replace_findinmap(json_path, data, input):
    proceed = False
    if isinstance(input, list) and len(input) == 3:
        proceed = True
    if proceed:
        parser_string = "Mappings"
        for level in input:
            parser_string = ".".join((parser_string, level))
        clean_string = clean_location(parser_string)
        value = parse(clean_string).find(data)[0].value
        json_path.update(data, value)

def get_condition_value(data, input):
    parser_string = ".".join(("$.Conditions", input))
    clean_string = clean_location(parser_string)
    value = parse(clean_string).find(data)[0].value
    return value

def replace_condition(json_path, data, input):
    if isinstance(input, str):
        value = get_condition_value(data, input)
        # Stop update from overwriting field if not in the Conditions section
        if "Conditions" not in str(json_path):
            json_path = json_path.child(Fields('Condition'))
        if type(value) is bool:
            json_path.update(data, value)

def get_exported_value(exports, export_name):
    try:
        value = exports[export_name]
    except KeyError:
        value = None
    return value

def replace_sub(json_path, data, parameters, input, region, partition, account_number, stack_name):
    sub_reg = '(\\${)((?:AWS::)?\\w+)(})'
    if isinstance(input, str):
        instances = re.findall(sub_reg, input)
        for instance in instances:
            param_name = instance[1]
            value = get_ref_value(parameters, param_name, region, partition, account_number, stack_name)
            if value is not None:
                pattern = "".join(('(\\${)(', instance[1], ')(})'))
                input = re.sub(pattern, value, input, count=1)
        json_path.update(data, input)
    if isinstance(input, list):
        output_string = input[0]
        output_params = input[1]
        instances = re.findall(sub_reg, output_string)
        for instance in instances:
            param_name = instance[1]
            try:
                param_value = output_params[param_name]
            except KeyError:
                param_value = get_ref_value(parameters, param_name, region, partition, account_number, stack_name)
            if isinstance(param_value, (str, int)):
                pattern = "".join(('(\\${)(', param_name, ')(})'))
                output_string = re.sub(pattern, param_value, output_string)
                try:
                    del output_params[param_name]
                except KeyError:
                    logger.info("Skipping replacement of key [{}] from string: {}".format(param_name,output_string))
        if output_params == {}:
            json_path.update(data, output_string)
        else:
            output = { "Fn::Sub" : [ output_string, output_params ] }
            json_path.update(data, output)

def replace_importvalue(json_path, data, input, exports):
    proceed = False
    if exports is not None:
        proceed = True
    if proceed:
        value = get_exported_value(exports, input)
        if value is not None:
            json_path.update(data, value)

def replace_getazs(json_path, data, azs):
    proceed = False
    if azs is not None:
        proceed = True
    if proceed:
        json_path.update(data, azs)

def replace_getatt(json_path, data, input):
    pass

def replace_cidr(json_path, data, input):
    proceed = False
    if isinstance(input, list):
        if len(input) == 3:
            proceed = True
    if proceed:
        network = ipaddress.ip_network(input[0])
        max = network.max_prefixlen
        mask = max - int(input[2])
        subnet_obj = list(network.subnets(new_prefix=mask))
        value = [subnet_obj[count].exploded for count in range(0, int(input[1]))]
        json_path.update(data, value)

def replace_base64(json_path, data, input):
    proceed = False
    if isinstance(input, str):
        proceed = True
    if proceed:
        utf8_string = input.encode("utf-8")
        value = base64.b64encode(utf8_string).decode("utf-8")
        json_path.update(data, value)

def replace_and(json_path, data, input):
    proceed = False
    if isinstance(input, list) and len(input) >= 2 and len(input) <= 10:
        all_bool = True
        for item in input:
            if type(item) is not bool:
                all_bool = False
                break
        proceed = all_bool
    if proceed:
        value = True
        for item in input:
            if item is False:
                value = False
                break
        json_path.update(data, value)

def replace_equals(json_path, data, input):
    proceed = False
    if isinstance(input, list) and len(input) == 2:
        if not isinstance(input[0], (list,dict)) and not isinstance(input[1], (list,dict)):
            proceed = True
    if proceed:
        if str(input[0]) == str(input[1]):
            value = True
        else:
            value = False
        json_path.update(data, value)

def replace_if(json_path, data, input):
    proceed = False
    if isinstance(input, list):
        proceed = True
    if proceed:
        condition = None
        if isinstance(input[0], bool):
            condition = input[0]
        elif isinstance(input[0], str):
            condition = get_condition_value(data, input[0])
        if condition is True:
            value = input[1]
        elif condition is False:
            value = input[2]
        if isinstance(condition, bool):
            json_path.update(data, value)
            if isinstance(value, dict) and "Ref" in value.keys():
                if value["Ref"] == "AWS::NoValue":
                    json_path.filter(lambda x: x != 'AWS::NoValue', data)

def replace_not(json_path, data, input):
    proceed = False
    if isinstance(input, list) and len(input) == 1:
        if isinstance(input[0], bool):
            proceed = True
    if proceed:
        value = not input[0]
        json_path.update(data, value)

def replace_or(json_path, data, input):
    proceed = False
    if isinstance(input, list) and len(input) >= 2 and len(input) <= 10:
        all_bool = True
        for item in input:
            if type(item) is not bool:
                all_bool = False
                break
        proceed = all_bool
    if proceed:
        value = False
        for item in input:
            if item is True:
                value = True
                break
        json_path.update(data, value)

def parse_location(json_full_path):
    parts = json_full_path.split(".")
    func = parts[-1]
    parts.remove(func)
    parent = ".".join(parts)
    return(parent, func)

def locate_all_to_replace(parser, data):
    intrinsic_funcs = [
    'Ref',
    'Condition',
    'Fn::Sub',
    'Fn::Split',
    'Fn::Select',
    'Fn::Join',
    'Fn::ImportValue',
    'Fn::GetAZs',
    'Fn::GetAtt',
    'Fn::FindInMap',
    'Fn::Cidr',
    'Fn::Base64',
    'Fn::And',
    'Fn::Equals',
    'Fn::If',
    'Fn::Not',
    'Fn::Or'
    ]
    locations = []
    for func in intrinsic_funcs:
        loc = [str(match.full_path) for match in parser.find(data) if (isinstance(match.value, (dict, list, str)) and str(match.path) == func)]
        locations.extend(loc)
    locations.sort(key=lambda x: len(x), reverse=True)
    return locations

def process_values(parser, data, parameters, region, partition, account_number, stack_name, az_list, cf_exports):
    locations = locate_all_to_replace(parser, data)
    for location in locations:
        process_template(location, data, parameters, region, partition, account_number, stack_name, az_list, cf_exports)

def get_azs(region):
    logger.info("Getting availability zones in region: {}...".format(region))
    try:
        ec2 = boto3.client('ec2', region_name=region)
        response = ec2.describe_availability_zones(
            Filters=[
                {
                    'Name': 'region-name',
                    'Values': [region]
                },
                {
                    'Name': 'zone-type',
                    'Values': ['availability-zone']
                }
            ]
        )
        output = [zone['ZoneName'] for zone in response['AvailabilityZones']]
        return output
    except ClientError as err:
        logger.info("Unable to get availability zones due to: {}".format(err.response['Error']['Message']))
        return None
    except NoCredentialsError as err:
        logger.info("Unable to get availability zones due to: No AWS Credentials Found")
        return None

def get_cf_exports(region):
    logger.info("Getting exported values from CloudFormation...")
    try:
        output = {}
        cf = boto3.client('cloudformation', region_name=region)
        paginator = cf.get_paginator('list_exports')
        iterator = paginator.paginate()
        for page in iterator:
            exports = page['Exports']
            for export in exports:
                output[export['Name']] = export['Value']
        return output
    except ClientError as err:
        logger.info("Unable to get export values due to: {}".format(err.response['Error']['Message']))
        return None
    except NoCredentialsError as err:
        logger.info("Unable to get export values due to: No AWS Credentials Found")
        return None

def remove_resources_with_false_condition(data, section="Resources"):
    parser_string = ".".join(("$", section, "*", "Condition"))
    parser = parse(parser_string)
    replace_line = [str(match.full_path) for match in parser.find(data) if (isinstance(match.value, bool) and match.value is True)]
    replace_resource = [str(match.full_path) for match in parser.find(data) if (isinstance(match.value, bool) and match.value is False)]
    for line in replace_line:
        parse(line).filter(lambda x: x, data)
    for resource in replace_resource:
        resource_string = ".".join((resource, "`parent`"))
        location = [str(match.full_path) for match in parse(resource_string).find(data)][0]
        parse(location).filter(lambda x: not x['Condition'], data)


def resolve_template(template_path, parameter_path, accountnumber, partition, region, prefix):
    stack_name = "-".join((prefix, template_path.stem))
    parameters = load_parameters(parameter_path)
    json_data = convert_to_json(template_path)
    all_parser = parse("$.*..*")
    json_locations = locate_all_to_replace(all_parser, json_data)
    actions = [x.split(".")[-1] for x in json_locations]
    if "Fn::GetAZs" in actions:
        az_list = get_azs(region)
    else:
        az_list = None
    if "Fn::ImportValue" in actions:
        cf_exports = get_cf_exports(region)
    else:
        cf_exports = None
    # Process data multiple times to process previously unrendered data
    for x in range(0, 3):
        process_values(all_parser, json_data, parameters, region, partition, accountnumber, stack_name, az_list, cf_exports)
    remove_resources_with_false_condition(json_data, "Resources")
    remove_resources_with_false_condition(json_data, "Outputs")
    json_string = json.dumps(json_data, indent=2, default=str)
    rendered_template = create_test_file(stack_name, json_string)
    return rendered_template

def load_parameters(parameter_path):
    #TODO - Add way to grab default values if parameter is missing. Probably need a function to get parameter list from the template
    #Coud probably reuse the logic from the stack class
    if not parameter_path.exists():
        logger.error("Parameter file [{}] does not exist!".format(parameter_path.as_posix()))
        sys.exit(1)
    else:
        json_data = convert_to_json(parameter_path)
        return json_data

def validate_templates(template_path, rules_folder_path):
    guard_commands = [
        "cfn-guard",
        "validate",
        "-r",
        rules_folder_path.as_posix(),
        "-d",
        template_path.as_posix()
    ]
    code = subprocess.run(guard_commands).returncode
    return code

def main(template_name, parameter_file=None, account_number="123456789012", partition="aws", region="us-east-1", prefix="travis-test"):
    root_dir = Path(__file__).parents[1]
    template_path = root_dir / "templates" / template_name
    if parameter_file is not None:
        parameter_path = root_dir / "parameters" / parameter_file
    else:
        parameter_path = root_dir / "parameters" / ".".join((template_path.stem, "json"))
    rendered = resolve_template(template_path, parameter_path, account_number, partition, region, prefix)
    rules_dir = root_dir / "rules"
    code = validate_templates(rendered, rules_dir)
    sys.exit(code)

if __name__ == "__main__":
    main(args['template'], args['parameters'])
