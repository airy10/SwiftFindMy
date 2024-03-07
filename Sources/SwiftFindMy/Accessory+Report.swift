//
//  File.swift
//  
//
//  Created by Airy ANDRE on 07/03/2024.
//

import Foundation

/// Helpers to fetch reports for some time interval
extension FindMyAccessory {

    public func keys(dateFrom: Date, dateTo: Date? = nil) -> any Collection<KeyPair> {

        var keys : Set<KeyPair> = []

        let dateTo = dateTo ?? Date.now

        var date = max(dateFrom, pairedAt)
        while date < dateTo {
            let newKeys = self.keys(at: date)
            keys.formUnion(newKeys)
            date += 15.0 * 60.0
        }

        return keys
    }

    public func fetchReports(account: BaseAppleAccount, dateFrom: Date, dateTo: Date? = nil) async throws -> [LocationReport] {

        print("Generating keys ----------------------", Date.now, ":")
        let keys = keys(dateFrom: dateFrom, dateTo: dateTo)
        print("Done            ----------------------", Date.now, ":")

        let reports = try  await account.fetchReports(
            keys: keys,
            dateFrom: dateFrom,
            dateTo: dateTo
        )

        let result = reports.reduce(into: []) {
            $0.append(contentsOf: $1.value)
        }
        return result.sorted()
    }

    /// See `BaseAppleAccount.fetch_last_reports
    public func fetchLastReports(account: BaseAppleAccount, hours: Int = 7 * 24) async throws -> [LocationReport] {

        let fromDate = Date.now - Double(hours) * 3600.0

        // number of slots until first 4 am

        return try await fetchReports(account: account, dateFrom: fromDate)
    }
}
