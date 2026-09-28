# U.S. operator guide

Reviewed September 27, 2026. Concert supplies controls to support lawful operation; it does not certify that a business complies with every federal, state or local requirement. Applicability depends on the operator's business, customers, location, custody/control of assets and the service sold. Obtain U.S. legal and tax advice for the actual deployment before accepting real payments.

## What the implementation does

- Requires an authenticated policy decision before new production payments settle or NFT access is granted. Timeout, malformed response, denial or expired assessment denies admission. Mainnet cannot be enabled under `test_mode`.
- Checks the payer established by cryptographic verification, not a wallet address supplied as an unsigned assertion. HBAR payments are restricted to one debited payer.
- Displays the merchant, native-asset price, recipient, pass duration, capacity limitation, terms, refund policy and privacy link before the browser asks for a payment. A consent checkbox is required. Unattended clients require an explicit budget, recipient and terms acceptance.
- Maintains settlement records with atomic amounts, payer, recipient, network, transaction, timestamp and policy assessment ID. It never asks a visitor for a private key or recovery phrase.
- Preserves a free FIFO queue and provides short-lived NFT proof without requesting an NFT transfer. A failed payment does not automatically sign another authorization.

These are engineering measures. The code does not supply a sanctions intelligence feed, identify beneficial owners, perform KYC, obtain licenses, calculate tax, file reports, or enforce all rules on the upstream business. Existing paid grants are not screened on every HTTP request; their configured duration is the maximum normal interval before another grant decision. Add an operational emergency-denial process appropriate to the service.

## Sanctions and policy service

OFAC's [virtual-currency industry guidance](https://ofac.treasury.gov/media/913571/download?inline=) describes risk-based sanctions compliance, including screening, geographic information and internal controls. A list of known wallet addresses alone is insufficient. Consider current sanctions programs, counterparties, location and relevant transaction risk. OFAC's [50 Percent Rule](https://ofac.treasury.gov/faqs/401) can apply to entities owned in aggregate by blocked persons even when those entities are not individually named on a list.

Integrate an operator-controlled service with an appropriate screening provider and review process. Configure `policy_url` and a separate `CONCERT_POLICY_TOKEN`. Concert sends an authenticated POST:

```json
{
  "network": "xrpl:0",
  "payer": "VERIFIED_PUBLIC_ADDRESS",
  "action": "payment",
  "requirements": {"scheme":"exact","network":"xrpl:0","asset":"XRP","amount":"100000","payTo":"MERCHANT","maxTimeoutSeconds":60},
  "client_ip": "CANONICAL_CLIENT_IP",
  "merchant": "OPERATOR_NAME"
}
```

Actions are `payment`, `payment_retry`, or `nft`. NFT requests have empty payment requirements. Resolve your merchant/customer policy context inside that service; a wallet address does not establish a person's identity. Do not use a user-provided forwarding header as a substitute for correctly configured trusted proxies.

Only an HTTP-success response with `decision: "allow"`, a nonempty `assessment_id`, and an `expires_at` UTC RFC3339 timestamp strictly in the future and no more than ten minutes away is accepted:

```json
{"decision":"allow","assessment_id":"YOUR_PROVIDER_CASE_ID","expires_at":"FUTURE_RFC3339_TIMESTAMP"}
```

The timestamp above is a placeholder, not an executable allow-all sample. Everything else denies the transaction. Your service must authenticate callers, refresh its data, retain the supporting assessment, handle review cases, and follow applicable blocking/rejection/reporting procedures. Do not automatically refund a potentially blocked transaction: obtain the appropriate legal determination first. Concert deliberately does not implement automatic refunds. Test mode without a policy URL bypasses screening only for allowed test-network identifiers.

## Business-model and licensing assessment

[FinCEN FIN-2019-G001](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-certain-business-models) explains how existing Bank Secrecy Act rules apply to different convertible-virtual-currency business models. A direct payment for an operator's own service and accepting/transmitting value for someone else can have different consequences. Self-hosting, an open-source license, a fee sponsor, or the label “noncustodial” does not settle the analysis. Have counsel assess money-transmitter/MSB status, applicable AML/reporting duties, state licensing and any obligations of a third-party facilitator or payment processor. Reassess before adding exchange, pooled balances, custodial wallets, routing for other merchants, or payouts.

NFT eligibility is access control. This package makes no determination about the legal status of a particular NFT, its sale or promotion. The operator remains responsible for the upstream product and its applicable age, privacy, licensing, consumer and other restrictions.

## Tax records and consumer terms

The [IRS digital-assets guidance](https://www.irs.gov/filing/digital-assets) treats digital assets as property and requires relevant transaction records, including U.S.-dollar fair market value for assets received as business payment. Receipt of a payment and later disposal can create different reporting events. Have a qualified tax adviser assess income, basis, sales tax and any information-reporting obligations for the operator's activities; operating this proxy does not automatically establish broker status.

Export a consistent journal backup with:

```sh
python3 scripts/export-payments.py /private/backup/fastlane.jsonl -o payments.csv
```

The export preserves exact native units and transaction identifiers. USD value and valuation source columns are intentionally blank. Add the appropriate contemporaneous valuation and retain fees, refunds, original on-chain settlement times and accounting records separately. Concert's `settled_utc` records when Concert confirmed the result; after recovery it can be later than the ledger transaction. The export is not a completed tax filing.

Publish an accurate refund/support policy explaining the duration, capacity limit, possible network fees, confirmation delay, outage handling and the service the payment actually buys. Avoid claiming immediate or guaranteed admission. If the upstream sells live-event tickets or short-term lodging, assess the [FTC Rule on Unfair or Deceptive Fees](https://www.ftc.gov/business-guidance/resources/rule-unfair-or-deceptive-fees-frequently-asked-questions), including its total-price requirements. The software name “Concert” alone does not place an unrelated service in that rule's scope. This generic interface does not replace an industry-specific compliant checkout.

Limit access to wallet/IP data, signed authorizations and receipt backups. Use encryption, a documented retention schedule and a privacy notice suited to the deployment. Keep replay-prevention records available for the lifetime of the system's payment validation; deleting them without a reviewed migration can enable reuse. Counsel should reconcile legal retention/deletion duties with that security requirement.

Before production, complete funded test-network trials for every enabled flow, review the limitations in [VALIDATION.md](VALIDATION.md), configure real policies and customer support, and review the particular business with its legal/tax advisers. No funded chain transactions or mainnet payments were performed while building this source package.
