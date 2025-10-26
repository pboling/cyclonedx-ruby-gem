# frozen_string_literal: true

# This file is part of CycloneDX Ruby Gem.
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OWASP Foundation. All Rights Reserved.
#

require 'securerandom'

require_relative 'bom_component'

module Cyclonedx
  module BomHelpers
    module_function

    def cyclonedx_xml_namespace(spec_version)
      "http://cyclonedx.org/schema/bom/#{spec_version}"
    end

    def purl(name, version)
      "pkg:gem/#{name}@#{version}"
    end

    def random_urn_uuid
      "urn:uuid:#{SecureRandom.uuid}"
    end

    # Determine if the selected spec version supports metadata/tools (>= 1.2)
    def metadata_supported?(spec_version)
      %w[1.2 1.3 1.4 1.5 1.6 1.7].include?(spec_version)
    end

    # Identity of this producer tool
    def tool_identity
      {
        vendor: 'CycloneDX',
        name: 'cyclonedx-ruby',
        version: ::Cyclonedx::Ruby::Version::VERSION
      }
    end

    def build_bom(gems, format, spec_version, include_metadata: false)
      if format == 'json'
        build_json_bom(gems, spec_version, include_metadata: include_metadata)
      else
        build_bom_xml(gems, spec_version, include_metadata: include_metadata)
      end
    end

    def build_json_bom(gems, spec_version, include_metadata: false)
      bom_hash = {
        bomFormat: 'CycloneDX',
        specVersion: spec_version,
        serialNumber: random_urn_uuid,
        version: 1,
        components: []
      }

      # Optionally include metadata.tools when supported by selected spec
      if include_metadata && metadata_supported?(spec_version)
        ti = tool_identity
        ti = ti.compact # omit nil values like version
        bom_hash[:metadata] = {
          tools: [ti]
        }
      end

      gems.each do |gem|
        bom_hash[:components] += Cyclonedx::BomComponent.new(gem).hash_val
      end

      JSON.pretty_generate(bom_hash)
    end

    def build_bom_xml(gems, spec_version, include_metadata: false)
      builder = Nokogiri::XML::Builder.new(encoding: 'UTF-8') do |xml|
        attributes = { 'xmlns' => cyclonedx_xml_namespace(spec_version), 'version' => '1', 'serialNumber' => random_urn_uuid }
        xml.bom(attributes) do
          # Optionally include metadata.tools when supported by selected spec
          if include_metadata && metadata_supported?(spec_version)
            xml.metadata do
              xml.tools do
                xml.tool do
                  xml.vendor tool_identity[:vendor]
                  xml.name tool_identity[:name]
                  xml.version tool_identity[:version] if tool_identity[:version]
                end
              end
            end
          end

          xml.components do
            gems.each do |gem|
              xml.component('type' => 'library') do
                xml.name gem['name']
                xml.version gem['version']
                xml.description gem['description']
                xml.hashes  do
                  xml.hash_ gem['hash'], alg: 'SHA-256'
                end
                if gem['license_id']
                  xml.licenses do
                    xml.license do
                      xml.id gem['license_id']
                    end
                  end
                elsif gem['license_name']
                  xml.licenses do
                    xml.license do
                      xml.name gem['license_name']
                    end
                  end
                end
                # The globally scoped legacy `Object#purl` method breaks the Nokogiri builder context
                # Fortunately Nokogiri has a built-in workaround, adding an underscore to the method name.
                # The resulting XML tag is still `<purl>`.
                # Globally scoped legacy `Object#purl` will be removed in v2.0.0, and this hack can be removed then.
                xml.purl_ gem['purl']
              end
            end
          end
        end
      end

      builder.to_xml
    end

    def get_gem(name, version, logger)
      url = "https://rubygems.org/api/v1/versions/#{name}.json"
      begin
        RestClient.proxy = ENV.fetch('http_proxy', nil)
        response = RestClient::Request.execute(method: :get, url: url, read_timeout: 2, open_timeout: 2)
        body = JSON.parse(response.body)
        body.select { |item| item['number'] == version.to_s }.first
      rescue StandardError
        logger.warn("#{name} couldn't be fetched")
        nil
      end
    end
  end
end
