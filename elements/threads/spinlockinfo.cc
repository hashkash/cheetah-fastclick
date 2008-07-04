/*
 * spinlockinfo.{cc,hh} -- element stores spinlocks
 * Benjie Chen, Eddie Kohler
 *
 * Copyright (c) 2000 Massachusetts Institute of Technology
 * Copyright (c) 2008 Meraki, Inc.
 *
 * This software is being provided by the copyright holders under the GNU
 * General Public License, either version 2 or, at your discretion, any later
 * version. For more information, see the `COPYRIGHT' file in the source
 * distribution.
 */

#include <click/config.h>
#include "spinlockinfo.hh"
#include <click/glue.hh>
#include <click/confparse.hh>
#include <click/nameinfo.hh>
#include <click/error.hh>
CLICK_DECLS

SpinlockInfo::SpinlockInfo()
{
}

SpinlockInfo::~SpinlockInfo()
{
}

int
SpinlockInfo::configure(Vector<String> &conf, ErrorHandler *errh)
{
    int before = errh->nerrors();
    if (NameDB *ndb = NameInfo::getdb(NameInfo::T_SPINLOCK, this,
				      sizeof(Spinlock *), true)) {
	_spinlocks.reserve(conf.size());
	String name;
	for (int i = 0; i < conf.size(); ++i)
	    if (cp_string(conf[i], &name)) {
		_spinlocks.push_back(Spinlock());
		ndb->define(name, &_spinlocks.back(), sizeof(Spinlock *));
	    } else
		errh->error("bad NAME");
    }
    return (errh->nerrors() == before ? 0 : -1);
}

// template instance
#include <click/vector.cc>
CLICK_ENDDECLS
EXPORT_ELEMENT(SpinlockInfo)