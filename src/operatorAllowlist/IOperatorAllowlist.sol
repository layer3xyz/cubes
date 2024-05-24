// Copyright Immutable Pty Ltd 2018 - 2023
// SPDX-License-Identifier: Apache 2.0
pragma solidity 0.8.20;

/**
 * @notice Required interface of an OperatorAllowlist compliant contract
 */
interface IOperatorAllowlist {
    /**
     * @notice Returns true if an address is Allowlisted false otherwise
     *  @param target the address to be checked against the Allowlist
     */
    function isAllowlisted(address target) external view returns (bool);
}
