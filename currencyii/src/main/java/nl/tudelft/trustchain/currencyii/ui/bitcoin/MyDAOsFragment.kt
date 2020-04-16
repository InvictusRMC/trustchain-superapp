package nl.tudelft.trustchain.currencyii.ui.bitcoin

import android.os.Bundle
import android.util.Log
import android.view.*
import androidx.fragment.app.Fragment
import androidx.navigation.fragment.findNavController
import kotlinx.android.synthetic.main.fragment_my_daos.*
import nl.tudelft.ipv8.util.toHex
import nl.tudelft.trustchain.currencyii.R
import nl.tudelft.trustchain.currencyii.sharedWallet.SWJoinBlockTransactionData
import nl.tudelft.trustchain.currencyii.ui.BaseFragment

/**
 * A simple [Fragment] subclass.
 * Use the [MyDAOsFragment.newInstance] factory method to
 * create an instance of this fragment.
 */
class MyDAOsFragment : BaseFragment(R.layout.fragment_my_daos) {

    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)
        initMyDAOsView()
        initProposalsView()
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        // Inflate the layout for this fragment
        return inflater.inflate(R.layout.fragment_my_daos, container, false)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setHasOptionsMenu(true)
    }

    override fun onCreateOptionsMenu(menu: Menu, inflater: MenuInflater) {
        inflater.inflate(R.menu.dao_options, menu)
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            R.id.my_daos_plus_btn -> {
                Log.i("Coin", "Opened DAO plus modal")
                val dialog = MyDAOsAddDialog()
                dialog.setTargetFragment(this, 0)
                dialog.show(parentFragmentManager, "Add DAO")
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    private fun initMyDAOsView() {
        val sharedWalletBlocks = getCoinCommunity().fetchLatestJoinedSharedWalletBlocks()
        val publicKey = getTrustChainCommunity().myPeer.publicKey.keyToBin().toHex()
        val adaptor =
            SharedWalletListAdapter(this, sharedWalletBlocks, publicKey, "Click to enter DAO")
        my_daos_list_view.adapter = adaptor
        my_daos_list_view.setOnItemClickListener { _, view, position, id ->
            val block = sharedWalletBlocks[position]
            val blockData = SWJoinBlockTransactionData(block.transaction).getData()
            findNavController().navigate(
                MyDAOsFragmentDirections.actionMyDAOsFragmentToSharedWalletTransaction(
                    blockData.SW_UNIQUE_ID,
                    blockData.SW_VOTING_THRESHOLD,
                    blockData.SW_ENTRANCE_FEE,
                    blockData.SW_TRUSTCHAIN_PKS.size,
                    block.calculateHash().toHex()
                )
            )
            Log.i("Coin", "Clicked: $view, $position, $id")
        }
        if (sharedWalletBlocks.isEmpty()) {
            enrolled_text.text =
                "You are currently not enrolled in any DAOs. Press the + button to join or create one."
        }
    }

    private fun initProposalsView() {
        val adaptor =
            ProposalListAdapter(this, emptyList(), emptyList())
        proposal_list_view.adapter = adaptor
        my_daos_list_view.setOnItemClickListener { _, view, position, id ->
            Log.i("Coin", "Clicked: $view, $position, $id")
        }
    }
}
