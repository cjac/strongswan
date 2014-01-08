/*
 * Copyright (C) 2009 Martin Willi
 * Hochschule fuer Technik Rapperswil
 *
 * Copyright (C) 2014 C.J. Adams-Collier
 * ZeroLag Communications, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "ike_vendor.h"

#include <daemon.h>
#include <encoding/payloads/vendor_id_payload.h>

typedef struct private_ike_vendor_t private_ike_vendor_t;

/**
 * Private data of an ike_vendor_t object.
 */
struct private_ike_vendor_t {

  /**
   * Public ike_vendor_t interface.
   */
  ike_vendor_t public;

  /**
   * Associated IKE_SA
   */
  ike_sa_t *ike_sa;

  /**
   * Are we the inititator of this task
   */
  bool initiator;
};

/**
 * strongSwan specific vendor ID without version, MD5("strongSwan")
 */
static chunk_t strongswan_vid = chunk_from_chars(
  0x88,0x2f,0xe5,0x6d,0x6f,0xd2,0x0d,0xbc,
  0x22,0x51,0x61,0x3b,0x2e,0xbe,0x5b,0xeb
);

/**
 * CISCO specific vendor ID strings
 */
/*CISCO-DELETE-REASON*/
static chunk_t cisco_delete_vid = chunk_from_chars(
  0x43,0x49,0x53,0x43,0x4f,0x2d,
  0x44,0x45,0x4c,0x45,0x54,0x45,0x2d,
  0x52,0x45,0x41,0x53,0x4f,0x4e
);
/*CISCO(COPYRIGHT)&Copyright (c) 2009 Cisco Systems, Inc.*/
static chunk_t cisco_2k9_vid = chunk_from_chars(
  0x43,0x49,0x53,0x43,0x4f,
  0x28,0x43,0x4f,0x50,0x59,0x52,0x49,0x47,0x48,0x54,0x29,0x26,
  0x43,0x6f,0x70,0x79,0x72,0x69,0x67,0x68,0x74,0x20,
  0x28,0x63,0x29,0x20,0x32,0x30,0x30,0x39,0x20,
  0x43,0x69,0x73,0x63,0x6f,0x20,0x53,0x79,0x73,0x74,0x65,0x6d,0x73,0x2c,0x20,0x49,0x6e,0x63,0x2e
);
/**
 * vendor ID indicates that peer supports fragmentation
 * http://msdn.microsoft.com/en-us/library/cc233219.aspx
 * http://www.cisco.com/en/US/docs/ios-xml/ios/sec_conn_ikevpn/configuration/15-1mt/Fragmentation_of_IKE_Packets.html
 * perl -MDigest::MD5 -e 'print Digest::MD5::md5_hex("FRAGMENTATION"), "\n"'
 */
static chunk_t fragmentation_vid = chunk_from_chars(
  0x40,0x48,0xb7,0xd5,0x6e,0xbc,0xe8,0x85,0x25,0xe7,0xde,0x7f,0x00,0xd6,0xc2,0xd3
);

METHOD(task_t, build, status_t,
  private_ike_vendor_t *this, message_t *message)
{
  if (lib->settings->get_bool(lib->settings,
                "%s.send_vendor_id", FALSE, charon->name))
  {
    vendor_id_payload_t *vid;

    vid = vendor_id_payload_create_data(VENDOR_ID,
                      chunk_clone(strongswan_vid));
    message->add_payload(message, &vid->payload_interface);
  }

  return this->initiator ? NEED_MORE : SUCCESS;
}

METHOD(task_t, process, status_t,
  private_ike_vendor_t *this, message_t *message)
{
  enumerator_t *enumerator;
  payload_t *payload;

  enumerator = message->create_payload_enumerator(message);
  while (enumerator->enumerate(enumerator, &payload))
  {
    if (payload->get_type(payload) == VENDOR_ID)
    {
      vendor_id_payload_t *vid;
      chunk_t data;

      vid = (vendor_id_payload_t*)payload;
      data = vid->get_data(vid);

      if (chunk_equals(data, strongswan_vid))
      {
        DBG1(DBG_IKE, "received strongSwan vendor ID");
        this->ike_sa->enable_extension(this->ike_sa, EXT_STRONGSWAN);
      }
      else if(chunk_equals(data, cisco_delete_vid))
      {
        DBG1(DBG_IKE, "received CISCO-DELETE-REASON vendor ID");
      }
      else if(chunk_equals(data, cisco_2k9_vid))
      {
        DBG1(DBG_IKE, "received 2009 Cisco Systems, Inc. vendor ID");
      }
      else if(chunk_equals(data, fragmentation_vid))
      {
        DBG1(DBG_IKE, "received FRAGMENTATION vendor ID");
      }
      else
      {
        DBG1(DBG_ENC, "received unknown vendor ID: %#B", &data);
      }
    }
  }
  enumerator->destroy(enumerator);

  return this->initiator ? SUCCESS : NEED_MORE;
}

METHOD(task_t, migrate, void,
  private_ike_vendor_t *this, ike_sa_t *ike_sa)
{
  this->ike_sa = ike_sa;
}

METHOD(task_t, get_type, task_type_t,
  private_ike_vendor_t *this)
{
  return TASK_IKE_VENDOR;
}

METHOD(task_t, destroy, void,
  private_ike_vendor_t *this)
{
  free(this);
}

/**
 * See header
 */
ike_vendor_t *ike_vendor_create(ike_sa_t *ike_sa, bool initiator)
{
  private_ike_vendor_t *this;

  INIT(this,
    .public = {
      .task = {
        .build = _build,
        .process = _process,
        .migrate = _migrate,
        .get_type = _get_type,
        .destroy = _destroy,
      },
    },
    .initiator = initiator,
    .ike_sa = ike_sa,
  );

  return &this->public;
}
