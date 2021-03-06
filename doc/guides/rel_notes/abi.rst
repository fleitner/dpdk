ABI policy
==========

See the :doc:`guidelines document for details of the ABI policy </guidelines/versioning>`.
ABI deprecation notices are to be posted here.


Examples of Deprecation Notices
-------------------------------

* The Macro #RTE_FOO is deprecated and will be removed with version 2.0, to be replaced with the inline function rte_bar()
* The function rte_mbuf_grok has been updated to include new parameter in version 2.0.  Backwards compatibility will be maintained for this function until the release of version 2.1
* The members struct foo have been reorganized in release 2.0.  Existing binary applications will have backwards compatibility in release 2.0, while newly built binaries will need to reference new structure variant struct foo2.  Compatibility will be removed in release 2.2, and all applications will require updating and rebuilding to the new structure at that time, which will be renamed to the original struct foo.
* Significant ABI changes are planned for the librte_dostuff library.  The upcoming release 2.0 will not contain these changes, but release 2.1 will, and no backwards compatibility is planned due to the invasive nature of these changes.  Binaries using this library built prior to version 2.1 will require updating and recompilation.


Deprecation Notices
-------------------

* Significant ABI changes are planned for struct rte_eth_dev to support up to
  1024 queues per port. This change will be in release 2.2.
  There is no backward compatibility planned from release 2.2.
  All binaries will need to be rebuilt from release 2.2.

* The Macros RTE_HASH_BUCKET_ENTRIES_MAX and RTE_HASH_KEY_LENGTH_MAX are
  deprecated and will be removed with version 2.2.

* Significant ABI changes are planned for struct rte_mbuf, struct rte_kni_mbuf,
  and several ``PKT_RX_`` flags will be removed, to support unified packet type
  from release 2.1. Those changes may be enabled in the upcoming release 2.1
  with CONFIG_RTE_NEXT_ABI.

* librte_malloc library has been integrated into librte_eal. The 2.1 release
  creates a dummy/empty malloc library to fulfill binaries with dynamic linking
  dependencies on librte_malloc.so. Such dummy library will not be created from
  release 2.2 so binaries will need to be rebuilt.

* The following fields have been deprecated in rte_eth_stats:
  imissed, ibadcrc, ibadlen, imcasts, fdirmatch, fdirmiss,
  tx_pause_xon, rx_pause_xon, tx_pause_xoff, rx_pause_xoff
