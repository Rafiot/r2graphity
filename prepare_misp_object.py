#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pefile
import pydeep
from pymisp import MISPEvent, MISPAttribute
import os
from io import BytesIO
from hashlib import md5, sha1, sha256, sha512
import magic
import math
from collections import Counter
import json
import uuid
import abc

misp_objects_path = './misp-objects/objects'


class MISPObjectException(Exception):
    pass


class InvalidMISPObject(MISPObjectException):
    """Exception raised when an object doesn't contains the required field(s)"""
    pass


class MISPObjectGenerator(metaclass=abc.ABCMeta):

    def __init__(self, object_definition):
        with open(os.path.join(misp_objects_path, object_definition), 'r') as f:
            self.definition = json.load(f)
        self.misp_event = MISPEvent()
        self.uuid = str(uuid.uuid4())
        self.links = []

    def _fill_object(self, values, strict=True):
        if strict:
            self._validate(values)
        # Create an empty object based om the object definition
        empty_object = self.__new_empty_object(self.definition)
        if self.links:
            # Set the links to other objects
            empty_object["ObjectReference"] = []
            for link in self.links:
                uuid, comment = link
                empty_object['ObjectReference'].append({'referenced_object_uuid': uuid, 'comment': comment})
        for object_type, value in values.items():
            # Add all the values as MISPAttributes to the current object
            if value.get('value') is None:
                continue
            # Initialize the new MISPAttribute
            attribute = MISPAttribute(self.misp_event.describe_types)
            # Get the misp attribute type from the definition
            value['type'] = self.definition['attributes'][object_type]['misp-attribute']
            if value.get('disable_correlation') is None:
                # The correlation can be disabled by default in the object definition.
                # Use this value if it isn't overloaded by the object
                value['disable_correlation'] = self.definition['attributes'][object_type].get('disable_correlation')
            if value.get('to_ids') is None:
                # Same for the to_ids flag
                value['to_ids'] = self.definition['attributes'][object_type].get('to_ids')
            # Set all the values in the MISP attribute
            attribute.set_all_values(**value)
            # Finalize the actual MISP Object
            empty_object['ObjectAttribute'].append({'type': object_type, 'Attribute': attribute._json()})
        return empty_object

    def _validate(self, dump):
        all_attribute_names = set(dump.keys())
        print(all_attribute_names)
        if self.definition.get('requiredOneOf'):
            if not set(self.definition['requiredOneOf']) & all_attribute_names:
                raise InvalidMISPObject('At least one of the following attributes is required: {}'.format(', '.join(self.definition['requiredOneOf'])))
        if self.definition.get('required'):
            for r in self.definition.get('required'):
                if r not in all_attribute_names:
                    raise InvalidMISPObject('{} is required is required'.format(r))
        return True

    def add_link(self, uuid, comment=None):
        self.links.append((uuid, comment))

    def __new_empty_object(self, object_definiton):
        return {'name': object_definiton['name'], 'meta-category': object_definiton['meta-category'],
                'uuid': self.uuid, 'description': object_definiton['description'],
                'version': object_definiton['version'], 'ObjectAttribute': []}

    @abc.abstractmethod
    def generate_attributes(self):
        # Contains the logic where all the values of the object are gathered
        pass

    @abc.abstractmethod
    def dump(self):
        # This method normalize the attributes to add to the object
        # It returns an python dictionary where the key is the type defined in the
        # object, and the value the value of the MISP Attribute
        pass


class FileObject(MISPObjectGenerator):

    def __init__(self, filepath):
        MISPObjectGenerator.__init__(self, 'file/definition.json')
        self.filepath = filepath
        with open(self.filepath, 'rb') as f:
            self.pseudo_file = BytesIO(f.read())
        self.data = self.pseudo_file.getvalue()
        self.generate_attributes()

    def generate_attributes(self):
        self.filename = os.path.basename(self.filepath)
        self.size = os.path.getsize(self.filepath)
        if self.size > 0:
            self.filetype = magic.from_buffer(self.data)
            self.entropy = self.__entropy_H(self.data)
            self.md5 = md5(self.data).hexdigest()
            self.sha1 = sha1(self.data).hexdigest()
            self.sha256 = sha256(self.data).hexdigest()
            self.sha512 = sha512(self.data).hexdigest()
            self.ssdeep = pydeep.hash_buf(self.data).decode()

    def __entropy_H(self, data):
        """Calculate the entropy of a chunk of data."""
        # NOTE: copy of the entropy function from pefile, the entropy of the
        # full file isn't computed

        if len(data) == 0:
            return 0.0

        occurences = Counter(bytearray(data))

        entropy = 0
        for x in occurences.values():
            p_x = float(x) / len(data)
            entropy -= p_x * math.log(p_x, 2)

        return entropy

    def dump(self):
        file_object = {}
        file_object['filename'] = {'value': self.filename}
        file_object['size-in-bytes'] = {'value': self.size}
        if self.size > 0:
            file_object['entropy'] = {'value': self.entropy}
            file_object['ssdeep'] = {'value': self.ssdeep}
            file_object['sha512'] = {'value': self.sha512}
            file_object['md5'] = {'value': self.md5}
            file_object['sha1'] = {'value': self.sha1}
            file_object['sha256'] = {'value': self.sha256}
            file_object['malware-sample'] = {'value': '{}|{}'.format(self.filename, self.md5), 'data': self.pseudo_file}
            # file_object['authentihash'] = self.
            # file_object['sha-224'] = self.
            # file_object['sha-384'] = self.
            # file_object['sha512/224'] = self.
            # file_object['sha512/256'] = self.
            # file_object['tlsh'] = self.
        return self._fill_object(file_object)


class PEObject(MISPObjectGenerator):

    def __init__(self, data):
        MISPObjectGenerator.__init__(self, 'pe/definition.json')
        self.data = data
        self.pe = pefile.PE(data=self.data)
        self.generate_attributes()

    def generate_attributes(self):
        if self.pe.is_dll():
            self.pe_type = 'dll'
        elif self.pe.is_driver():
            self.pe_type = 'driver'
        elif self.pe.is_exe():
            self.pe_type = 'exe'
        else:
            self.pe_type = 'unknown'
        # file_object['pehash'] = self.
        # General information
        self.imphash = self.pe.get_imphash()
        all_data = self.pe.dump_dict()
        if (all_data.get('Debug information') and all_data['Debug information'][0].get('TimeDateStamp') and
                all_data['Debug information'][0]['TimeDateStamp'].get('ISO Time')):
            self.compilation_timestamp = all_data['Debug information'][0]['TimeDateStamp']['ISO Time']
        if (all_data.get('OPTIONAL_HEADER') and all_data['OPTIONAL_HEADER'].get('AddressOfEntryPoint')):
            self.entrypoint_address = all_data['OPTIONAL_HEADER']['AddressOfEntryPoint']['Value']
        if all_data.get('File Info'):
            self.original_filename = all_data['File Info'][1].get('OriginalFilename')
            self.internal_filename = all_data['File Info'][1].get('InternalName')
            self.file_description = all_data['File Info'][1].get('FileDescription')
            self.file_version = all_data['File Info'][1].get('FileVersion')
            self.lang_id = all_data['File Info'][1].get('LangID')
            self.product_name = all_data['File Info'][1].get('ProductName')
            self.product_version = all_data['File Info'][1].get('ProductVersion')
            self.company_name = all_data['File Info'][1].get('CompanyName')
            self.legal_copyright = all_data['File Info'][1].get('LegalCopyright')
        # Sections
        self.sections = []
        if all_data.get('PE Sections'):
            pos = 0
            for s in all_data['PE Sections']:
                s_obj = self.pe.sections[pos]
                section = PESectionObject(s, s_obj.get_data())
                self.add_link(section.uuid, 'Section {} of PE'.format(pos))
                if ((self.entrypoint_address >= s['VirtualAddress']['Value']) and
                        (self.entrypoint_address < (s['VirtualAddress']['Value'] + s['Misc_VirtualSize']['Value']))):
                    self.entrypoint_section = (s['Name']['Value'], pos)  # Tuple: (section_name, position)
                pos += 1
                self.sections.append(section)
        self.nb_sections = len(self.sections)
        # TODO: TLSSection / DIRECTORY_ENTRY_TLS

    def dump(self):
        pe_object = {}
        pe_object['type'] = {'value': self.pe_type}
        if hasattr(self, 'imphash'):
            pe_object['imphash'] = {'value': self.imphash}
        if hasattr(self, 'original_filename'):
            pe_object['original-filename'] = {'value': self.original_filename}
        if hasattr(self, 'internal_filename'):
            pe_object['internal-filename'] = {'value': self.internal_filename}
        if hasattr(self, 'compilation_timestamp'):
            pe_object['compilation-timestamp'] = {'value': self.compilation_timestamp}
        if hasattr(self, 'entrypoint_section'):
            pe_object['entrypoint-section|position'] = {'value': '{}|{}'.format(*self.entrypoint_section)}
        if hasattr(self, 'entrypoint_address'):
            pe_object['entrypoint-address'] = {'value': self.entrypoint_address}
        if hasattr(self, 'file_description'):
            pe_object['file-description'] = {'value': self.file_description}
        if hasattr(self, 'file_version'):
            pe_object['file-version'] = {'value': self.file_version}
        if hasattr(self, 'lang_id'):
            pe_object['lang-id'] = {'value': self.lang_id}
        if hasattr(self, 'product_name'):
            pe_object['product-name'] = {'value': self.product_name}
        if hasattr(self, 'product_version'):
            pe_object['product-version'] = {'value': self.product_version}
        if hasattr(self, 'company_name'):
            pe_object['company-name'] = {'value': self.company_name}
        if hasattr(self, 'nb_sections'):
            pe_object['number-sections'] = {'value': self.nb_sections}
        return self._fill_object(pe_object)


class PESectionObject(MISPObjectGenerator):

    def __init__(self, section_info, data):
        MISPObjectGenerator.__init__(self, 'pe-section/definition.json')
        self.section_info = section_info
        self.data = data
        self.generate_attributes()

    def generate_attributes(self):
        self.name = self.section_info['Name']['Value']
        self.size = self.section_info['SizeOfRawData']['Value']
        if self.size > 0:
            self.entropy = self.section_info['Entropy']
            self.md5 = self.section_info['MD5']
            self.sha1 = self.section_info['SHA1']
            self.sha256 = self.section_info['SHA256']
            self.sha512 = self.section_info['SHA512']
            self.ssdeep = pydeep.hash_buf(self.data).decode()

    def dump(self):
        section = {}
        section['name'] = {'value': self.name}
        section['size-in-bytes'] = {'value': self.size}
        if self.size > 0:
            section['entropy'] = {'value': self.entropy}
            section['md5'] = {'value': self.md5}
            section['sha1'] = {'value': self.sha1}
            section['sha256'] = {'value': self.sha256}
            section['sha512'] = {'value': self.sha512}
            section['ssdeep'] = {'value': self.ssdeep}
        return self._fill_object(section)


def make_objects(filepath):
    misp_file = FileObject(filepath)
    try:
        misp_pe = PEObject(misp_file.data)
        misp_file.add_link(misp_pe.uuid, 'PE indicators')
        file_object = misp_file.dump()
        pe_object = misp_pe.dump()
        pe_sections = []
        for s in misp_pe.sections:
            pe_sections.append(s.dump())
        return file_object, pe_object, pe_sections
    except pefile.PEFormatError:
        pass
    file_object = misp_file.dump()
    return file_object, None, None


if __name__ == '__main__':
    import glob
    for f in glob.glob('/home/raphael/.viper/projects/troopers17/vt_samples/*/*'):
        fo, peo, seos = make_objects(f)
        #print(json.dumps([fo, peo, seos]))
        #break
