package nl.tudelft.trustchain.currencyii.ui.bitcoin

import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.TextView
import nl.tudelft.trustchain.currencyii.ui.BaseFragment
import nl.tudelft.trustchain.currencyii.R
import nl.tudelft.trustchain.currencyii.sharedWallet.SWSignatureAskBlockTD
import nl.tudelft.trustchain.currencyii.sharedWallet.SWTransferFundsAskBlockTD

class ProposalListAdapter(
    private val context: BaseFragment,
    private val signatureAskBlocks: List<SWSignatureAskBlockTD>,
    private val transferFundsBlocks: List<SWTransferFundsAskBlockTD>
) : BaseAdapter() {

    override fun getView(p0: Int, p1: View?, p2: ViewGroup?): View {
        val view = context.layoutInflater.inflate(R.layout.proposal_entry, null, false)

//        val item = signatureAskBlocks.union(transferFundsBlocks)
//        val blockData = SWJoinBlockTransactionData(getItem(p0)).getData()

        val walletId = view.findViewById<TextView>(R.id.proposal_wallet_id)
        val proposalId = view.findViewById<TextView>(R.id.proposal_id)

        walletId.text = ""
        proposalId.text = ""

        return view
    }

    override fun getItem(p0: Int): Any {
        return signatureAskBlocks.union(transferFundsBlocks).toList()[p0]
    }

    override fun getItemId(p0: Int): Long {
        return p0.toLong()
    }

    override fun getCount(): Int {
        return signatureAskBlocks.union(transferFundsBlocks).size
    }
}
