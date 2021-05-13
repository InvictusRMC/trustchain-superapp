package nl.tudelft.trustchain.ssi.ui.database

import android.annotation.SuppressLint
import android.graphics.Bitmap
import android.os.Bundle
import android.util.Log
import android.view.Menu
import android.view.MenuInflater
import android.view.MenuItem
import android.view.View
import android.widget.LinearLayout
import androidmads.library.qrgenearator.QRGContents
import androidmads.library.qrgenearator.QRGEncoder
import androidx.core.content.res.ResourcesCompat
import androidx.core.os.bundleOf
import androidx.core.view.isVisible
import androidx.lifecycle.lifecycleScope
import androidx.navigation.fragment.findNavController
import androidx.recyclerview.widget.DividerItemDecoration
import androidx.recyclerview.widget.LinearLayoutManager
import com.mattskala.itemadapter.ItemAdapter
import kotlinx.android.synthetic.main.fragment_database.*
import kotlinx.coroutines.*
import nl.tudelft.ipv8.attestation.communication.DEFAULT_TIME_OUT
import nl.tudelft.trustchain.common.ui.BaseFragment
import nl.tudelft.trustchain.common.util.viewBinding
import nl.tudelft.trustchain.ssi.Communication
import nl.tudelft.trustchain.ssi.R
import nl.tudelft.trustchain.ssi.databinding.FragmentDatabaseBinding
import nl.tudelft.trustchain.ssi.ui.dialogs.attestation.PresentAttestationDialog
import nl.tudelft.trustchain.ssi.ui.dialogs.attestation.RemoveAttestationDialog
import nl.tudelft.trustchain.ssi.ui.dialogs.misc.RendezvousDialog
import nl.tudelft.trustchain.ssi.util.encodeB64
import nl.tudelft.trustchain.ssi.util.formatAttestationToJSON
import nl.tudelft.trustchain.ssi.util.formatValueToJSON
import org.json.JSONObject

const val QR_CODE_VALUE_LIMIT = 200

class DatabaseFragment : BaseFragment(R.layout.fragment_database) {

    private val adapter = ItemAdapter()
    private val binding by viewBinding(FragmentDatabaseBinding::bind)

    lateinit var bitmap: Bitmap

    private var areFABsVisible = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setHasOptionsMenu(true)
        adapter.registerRenderer(
            DatabaseItemRenderer(
                {
                    setDatabaseItemAction(it)
                },
                {
                    RemoveAttestationDialog(it, ::loadDatabaseEntries).show(
                        parentFragmentManager,
                        this.tag
                    )
                }
            )
        )
    }

    override fun onCreateOptionsMenu(menu: Menu, inflater: MenuInflater) {
        menu.clear()
        inflater.inflate(R.menu.database_options_menu, menu)
        super.onCreateOptionsMenu(menu, inflater)
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        when (item.itemId) {
            R.id.action_settings -> {
                RendezvousDialog(callback = this::setPeerInfo).show(parentFragmentManager, "ig-ssi")
                return true
            }
            else -> {

            }
        }
        return super.onOptionsItemSelected(item)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        setListView()
        setPeerInfo()
        setFABs()
        loadDatabaseEntriesOnLoop()
    }

    private fun setListView() {
        binding.recyclerView.adapter = adapter
        binding.recyclerView.layoutManager = LinearLayoutManager(context)
        binding.recyclerView.addItemDecoration(
            DividerItemDecoration(
                context,
                LinearLayout.VERTICAL
            )
        )
    }

    private fun loadDatabaseEntriesOnLoop() {
        lifecycleScope.launchWhenStarted {
            while (isActive) {
                loadDatabaseEntries()
                delay(100)
            }
        }
    }

    private fun loadDatabaseEntries() {
        val channel =
            Communication.load()
        val entries = channel.getOfflineVerifiableAttributes()
            .mapIndexed { index, blob -> DatabaseItem(index, blob) }

        val areEqual = entries == adapter.items
        if (!areEqual) {
            adapter.updateItems(entries)
        }

        databaseTitle.text = "Attestations"
        txtAttestationCount.text = "${entries.size} entries"
        val textColorResId = if (entries.isNotEmpty()) R.color.green else R.color.red
        val textColor = ResourcesCompat.getColor(resources, textColorResId, null)
        txtAttestationCount.setTextColor(textColor)
        imgEmpty.isVisible = entries.isEmpty()
    }

    private fun setDatabaseItemAction(it: DatabaseItem) {
        val attributeName = it.attestation.attributeName
        val attributeValue = it.attestation.attributeValue

        val dialog = PresentAttestationDialog(
            attributeName,
            String(attributeValue)
        )
        dialog.show(
            parentFragmentManager,
            tag
        )
        val channel = Communication.load()
        lifecycleScope.launch {
            while (isActive) {
                val challenge = channel.generateChallenge()

                var secondaryQRCode: Bitmap? = null
                val presentation: String
                if (it.attestation.attributeValue.size > QR_CODE_VALUE_LIMIT) {
                    presentation =
                        formatAttestationToJSON(it.attestation, channel.myPeer.publicKey, challenge)
                    val secondaryPresentation =
                        formatValueToJSON(
                            it.attestation.attributeValue,
                            challenge
                        )
                    secondaryQRCode =
                        QRGEncoder(
                            secondaryPresentation,
                            null,
                            QRGContents.Type.TEXT,
                            1000
                        ).bitmap
                } else {
                    presentation = formatAttestationToJSON(
                        it.attestation,
                        channel.myPeer.publicKey,
                        challenge,
                        it.attestation.attributeValue
                    )
                }
                Log.d(
                    "ig-ssi",
                    "Presenting Attestation as QRCode: Size ${
                        presentation.length
                    }, Data: $presentation"
                )
                val bitmap = withContext(Dispatchers.Default) {
                    QRGEncoder(
                        presentation,
                        null,
                        QRGContents.Type.TEXT,
                        1000
                    ).bitmap
                }
                dialog.setQRCodes(bitmap, secondaryQRCode)
                dialog.startTimeout(DEFAULT_TIME_OUT)
                delay(DEFAULT_TIME_OUT)
            }
        }
    }

    @SuppressLint("ClickableViewAccessibility")
    private fun setFABs() {
        binding.addAttestationFab.visibility = View.GONE
        binding.addAuthorityFab.visibility = View.GONE
        binding.scanAttestationFab.visibility = View.GONE
        binding.addAttestationActionText.visibility = View.GONE
        binding.addAuthorityActionTxt.visibility = View.GONE
        binding.scanAttestationActionText.visibility = View.GONE

        binding.actionFab.setOnClickListener {
            if (!areFABsVisible) {
                binding.addAttestationFab.show()
                binding.addAuthorityFab.show()
                binding.scanAttestationFab.show()
                binding.addAttestationActionText.visibility = View.VISIBLE
                binding.addAuthorityActionTxt.visibility = View.VISIBLE
                binding.scanAttestationActionText.visibility = View.VISIBLE
                areFABsVisible = true
            } else {
                binding.addAttestationFab.hide()
                binding.addAuthorityFab.hide()
                binding.scanAttestationFab.hide()
                binding.addAttestationActionText.visibility = View.GONE
                binding.addAuthorityActionTxt.visibility = View.GONE
                binding.scanAttestationActionText.visibility = View.GONE
                areFABsVisible = false
            }
        }

        binding.addAttestationFab.setOnClickListener {
            val bundle = bundleOf("qrCodeHint" to "Scan signee public key", "intent" to 0)
            findNavController().navigate(
                DatabaseFragmentDirections.actionDatabaseFragmentToVerificationFragment().actionId,
                bundle
            )
        }

        binding.addAuthorityFab.setOnClickListener {
            val bundle = bundleOf("qrCodeHint" to "Scan signee public key", "intent" to 1)
            findNavController().navigate(
                DatabaseFragmentDirections.actionDatabaseFragmentToVerificationFragment().actionId,
                bundle
            )
        }

        binding.scanAttestationFab.setOnClickListener {
            val bundle = bundleOf("qrCodeHint" to "Scan attestation", "intent" to 2)
            findNavController().navigate(
                DatabaseFragmentDirections.actionDatabaseFragmentToVerificationFragment().actionId,
                bundle
            )
        }
    }

    private fun setPeerInfo() {
        binding.myPublicKey.text = Communication.load().myPeer.mid
        binding.publicKeyQRCode.setOnClickListener {
            if (it.scaleX > 1) {
                it.animate().scaleX(1f).scaleY(1f)
            } else {
                it.animate().scaleX(1.2f).scaleY(1.2f)
            }
        }

        lifecycleScope.launch {
            val data = JSONObject()
            data.put("presentation", "authority")
            val myPeer = Communication.load().myPeer
            val publicKey =
                encodeB64(myPeer.publicKey.keyToBin())
            data.put("public_key", publicKey)
            data.put("rendezvous", Communication.getActiveRendezvousToken())

            bitmap = QRGEncoder(data.toString(), null, QRGContents.Type.TEXT, 1000).bitmap
            try {
                binding.qrCodePlaceHolder.visibility = View.GONE
                binding.publicKeyQRCode.setImageBitmap(bitmap)
            } catch (e: IllegalStateException) {
                // This happens if we already switched screens.
            }
        }
    }
}