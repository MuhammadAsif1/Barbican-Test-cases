#!/bin/bash

################## ------- Varibales ----------###################
###-- 3 compute nodes ---##
compute_node1_ip='192.168.12.140'
compute_node2_ip='192.168.12.141'
compute_node3_ip='192.168.12.142'
###-- 3 controller nodes ---##
controller_node1_ip='192.168.12.143'
controller_node2_ip='192.168.12.144'
controller_node3_ip='192.168.12.145'
barbican_parameter='castellan.key_manager.barbican_key_manager.BarbicanKeyManager' # value of this parameter ----> castellan.key_manager.barbican_key_manager.BarbicanKeyManager
#verify glance is configured to use barbican
glance_parameter='True'

volume_template='LuksEncryptor-Template-256'
encrypted_volume='Encrypted-Test-Volume'
unencrypted_volume='volume-1'
private_key='private_key.pem'
public_key='public_key.pem'
cert_request='cert_request.csr'
signed_cert='x509_signing_cert.crt'
singned_cert_key='signing-cert'
cloud_file='/home/osp_admin/CentOS-7-x86_64-GenericCloud.qcow2'
signing_image='centos-7.signature'
signing_image_b64='centos-7.signature.b64'
image='centos_7_signed'
network='network1'
subnet='subnet1'
router='router1'
public_network='public'
flavor='flavor1'
security_group='----------'
instance='barbican_instance'

href_value=''
href_id=''

logs_directory='/home/osp_admin/barbican_logs/'
if [ -d "$logs_directory" ]; 
then
  echo "log directory exist"
else
  mkdir /home/osp_admin/barbican_logs/
fi
# one file will be created in this directory for each function defined below


############################################## ---- Functions ---------#####################################################

mkdir /home/osp_admin/barbican_keys

verify_glance_with_barbican()
{
  output1=$(ssh heat-admin@$compute_node1_ip 'cat /var/lib/config-data/puppet-generated/glance_api/etc/glance/glance-api.conf | grep castellan.key_manager.barbican_key_manager.BarbicanKeyManager') # this should be executed for that ----> cat /var/lib/config-data/puppet-generated/glance_api/etc/glance/glance-api.conf | grep castellan.key_manager.barbican_key_manager.BarbicanKeyManager
  echo $output1 > $logs_directory/verify_glance_with_barbican.log /// only first will over write 
  
  output2=$(ssh heat-admin@$compute_node2_ip 'cat /var/lib/config-data/puppet-generated/glance_api/etc/glance/glance-api.conf | grep castellan.key_manager.barbican_key_manager.BarbicanKeyManager')
  echo $output2 >> $logs_directory/verify_glance_with_barbican.log
  
  output3=$(ssh heat-admin@$compute_node3_ip 'cat /var/lib/config-data/puppet-generated/glance_api/etc/glance/glance-api.conf | grep castellan.key_manager.barbican_key_manager.BarbicanKeyManager')
  echo $output3 >> $logs_directory/verify_glance_with_barbican.log
  
  output4=$(ssh heat-admin@$compute_node1_ip 'crudini --get /var/lib/config-data/puppet-generated/nova_libvirt/etc/nova/nova.conf verify_glance_signatures')
  echo $output4 >> $logs_directory/verify_glance_with_barbican.log
  
  output5=$(ssh heat-admin@$compute_node2_ip 'crudini --get /var/lib/config-data/puppet-generated/nova_libvirt/etc/nova/nova.conf verify_glance_signatures')
  echo $output5 >> $logs_directory/verify_glance_with_barbican.log
  
  output6=$(ssh heat-admin@$compute_node3_ip 'crudini --get /var/lib/config-data/puppet-generated/nova_libvirt/etc/nova/nova.conf verify_glance_signatures')
  echo $output6 >> $logs_directory/verify_glance_with_barbican.log
  
  if [ $barbican_parameter = $output1 ] && [ $barbican_parameter = $output2 ] && [ $barbican_parameter = $output3 ] && [ $glance_parameter = $output4 ] && [ $glance_parameter = $output5 ] && [ $glance_parameter = $output6 ]
  then
    echo '========================================================================================='
    echo '========== Test Case executed Successfully, Glance is enabled to use Barbican ==========='
    echo '========================================================================================='
    echo '========== Test Case executed Successfully, Glance is enabled to use Barbican ===========' >> $logs_directory/verify_glance_with_barbican.log
  else
    echo '========================================================================================='
    echo '=============== Test Case Failed, Glance is not enabled to use Barbican ================='
    echo '========================================================================================='
    echo '=============== Test Case Failed, Glance is not enabled to use Barbican =================' >> $logs_directory/verify_glance_with_barbican.log
  fi   
}
#########################################################################
verify_cinder_uses_barbican()
{
  output1=$(ssh heat-admin@$controller_node1_ip 'cat /var/lib/config-data/puppet-generated/cinder/etc/cinder/cinder.conf | grep castellan.key_manager.barbican_key_manager.BarbicanKeyManager') # this should be executed for that ----> 'cat /var/lib/config-data/puppet-generated/cinder/etc/cinder/cinder.conf | grep castellan.key_manager.barbican_key_manager.BarbicanKeyManager
  echo $output1 > $logs_directory/verify_cinder_uses_barbican.log /// only first will over write
  
  output2=$(ssh heat-admin@$controller_node2_ip 'cat /var/lib/config-data/puppet-generated/cinder/etc/cinder/cinder.conf | grep castellan.key_manager.barbican_key_manager.BarbicanKeyManager')
  echo $output2 >> $logs_directory/verify_cinder_uses_barbican.log
  
  output3=$(ssh heat-admin@$controller_node1_ip 'cat /var/lib/config-data/puppet-generated/cinder/etc/cinder/cinder.conf | grep castellan.key_manager.barbican_key_manager.BarbicanKeyManager')
  echo $output3 >> $logs_directory/verify_cinder_uses_barbican.log
  
  if [ $barbican_parameter = $output1 ] && [ $barbican_parameter = $output2 ] && [ $barbican_parameter = $output3 ]
  then
    echo '========================================================================================='
    echo '========== Test Case executed Successfully, Cinder is enabled to use Barbican ==========='
    echo '========================================================================================='
    echo '========== Test Case executed Successfully, Cinder is enabled to use Barbican ===========' >> $logs_directory/verify_cinder_uses_barbican.log
  else
    echo '========================================================================================='
    echo '=============== Test Case Failed, Cinder is not enabled to use Barbican ================='
    echo '========================================================================================='
    echo '=============== Test Case Failed, Cinder is not enabled to use Barbican =================' >> $logs_directory/verify_cinder_uses_barbican.log
  fi   
}
###########################################################################
verify_nova_uses_barbican()
{
  output1=$(ssh heat-admin@$compute_node1_ip 'cat /var/lib/config-data/nova-libvirt/etc/nova/nova.conf | grep castellan.key_manager.barbican_key_manager.BarbicanKeyManager') # this should be executed for that ----> ' cat /var/lib/config-data/nova-libvirt/etc/nova/nova.conf | grep castellan.key_manager.barbican_key_manager.BarbicanKeyManager
  echo $output1 > $logs_directory/verify_nova_uses_barbican.log /// only first will over write
  output2=$(ssh heat-admin@$compute_node2_ip 'cat /var/lib/config-data/nova-libvirt/etc/nova/nova.conf | grep castellan.key_manager.barbican_key_manager.BarbicanKeyManager')
  echo $output2 >> $logs_directory/verify_nova_uses_barbican.log
  output3=$(ssh heat-admin@$compute_node3_ip 'cat /var/lib/config-data/nova-libvirt/etc/nova/nova.conf | grep castellan.key_manager.barbican_key_manager.BarbicanKeyManager')
  echo $output3 >> $logs_directory/verify_nova_uses_barbican.log
  if [ $barbican_parameter = $output1 ] && [ $barbican_parameter = $output2 ] && [ $barbican_parameter = $output3 ]
  then
    echo '========================================================================================='
    echo '========== Test Case executed Successfully, Cinder is enabled to use Barbican ==========='
    echo '========================================================================================='
    echo '========== Test Case executed Successfully, Cinder is enabled to use Barbican ===========' >> $logs_directory/verify_nova_uses_barbican.log
  else
    echo '========================================================================================='
    echo '=============== Test Case Failed, Cinder is not enabled to use Barbican ================='
    echo '========================================================================================='
    echo '=============== Test Case Failed, Cinder is not enabled to use Barbican =================' >> $logs_directory/verify_nova_uses_barbican.log
  fi   
}
############################################################################
encrypted_volume_creation()
{
  output=$(openstack volume type create --encryption-provider nova.volume.encryptors.luks.LuksEncryptor --encryption-cipher aes-xts-plain64 --encryption-key-size 256 --encryption-control-location front-end $volume_template)
  sleep 10
  echo $output
  echo $output > $logs_directory/encrypted_volume_creation.log
  
  output=$(openstack volume create --size 1 --type LuksEncryptor-Template-256 $encrypted_volume)
  sleep 1m
  echo $output
  echo $output >> $logs_directory/encrypted_volume_creation.log

  if [ $(openstack volume show testvolume | awk '/available/ {print $4}') = 'available']
  then
    echo '========================================================================================='
    echo '================= Test Case executed Successfully, Encrypted Volume is created =========='
    echo '========================================================================================='
    echo '================= Test Case executed Successfully, Encrypted Volume is created ==========' >> $logs_directory/encrypted_volume_creation.log
  else
    echo '========================================================================================='
    echo '======================= Test Case Failed, Encrypted volume not created =================='
    echo '========================================================================================='
    echo '======================= Test Case Failed, Encrypted volume not created ==================' >> $logs_directory/encrypted_volume_creation.log
  fi
  volume_id=$(openstack volume show $encrypted_volume | grep -w id)
}
#################################################################################
verify_addition_of_key_to_barbican_secret_store()
{
  rm -rf /home/osp_admin/barbican_keys/*
  ##Generate a private key and convert it to the required format
  output=$(openssl genrsa -out /home/osp_admin/barbican_keys/$private_key 1024)
  echo $output
  echo $output > $logs_directory/verify_addition_of_key_to_barbican_secret_store.log
  
  output=$(openssl rsa -pubout -in /home/osp_admin/barbican_keys/$private_key -out /home/osp_admin/barbican_keys/$public_key)
  echo $output
  echo $output >> $logs_directory/verify_addition_of_key_to_barbican_secret_store.log
  
  output=$(openssl req -new -key /home/osp_admin/barbican_keys/$private_key -out /home/osp_admin/barbican_keys/$cert_request)
  echo $output
  echo $output >> $logs_directory/verify_addition_of_key_to_barbican_secret_store.log
  
  output=$(openssl x509 -req -days 14 -in /home/osp_admin/barbican_keys/$cert_request -signkey /home/osp_admin/barbican_keys/$private_key -out /home/osp_admin/barbican_keys/$signed_cert)
  echo $output
  echo $output >> $logs_directory/verify_addition_of_key_to_barbican_secret_store.log
  
  ##Add the key to the barbican secret store
  href_value=$(openstack secret store --name $singned_cert_key --algorithm RSA --secret-type certificate --payload-content-type "application/octet-stream" --payload-content-encoding base64  --payload "$(base64 /home/osp_admin/barbican_keys/$signed_cert)" -c 'Secret href' -f value)  ###some doubts in this command
  echo $href_value
  echo $href_value >> $logs_directory/verify_addition_of_key_to_barbican_secret_store.log
  ###
  href_id=$(echo $href_value | awk -F '/' '{print $6}')
  echo $href_id
  echo $href_id >> $logs_directory/verify_addition_of_key_to_barbican_secret_store.log
  if [ $(openstack secret show $href_value | grep $singned_cert_key) != ' ' ]
  then
    echo "Barbican Secret Key added Successfully"
    echo "Barbican Secret Key added Successfully" >> $logs_directory/verify_addition_of_key_to_barbican_secret_store.log
  else
    echo "Barbican Secret Key Failed to add"
    echo "Barbican Secret Key Failed to add" >> $logs_directory/verify_addition_of_key_to_barbican_secret_store.log
    rm -rf /home/osp_Admin/barbican_keys/*
  fi
}
####################################################################################
creating_signed_image()
{
##call function inside it, if needed
  verify_addition_of_key_to_barbican_secret_store
  ##Use private_key.pem to sign the image and generate the .signature file
  output=$(openssl dgst -sha256 -sign /home/osp_admin/barbican_keys/$private_key -sigopt rsa_padding_mode:pss -out /home/osp_admin/barbican_keys/$signing_image /home/osp_admin/$cloud_file)
  echo $output
  echo $output > $logs_directory/creating_signed_image.log
  ##Convert the resulting .signature file into base64 format
  output=$(base64 -w 0 /home/osp_admin/barbican_keys/$signing_image > /home/osp_admin/barbican_keys/$signing_image_b64)
  echo $output
  echo $output >> $logs_directory/creating_signed_image.log
  ###Load the base64 value into a variable to use it in the subsequent command
  output=$(image_signature_b64=$(cat /home/osp_admin/barbican_keys/$signing_image_b64))
  echo $output
  echo $output >> $logs_directory/creating_signed_image.log
  ##### Upload the signed image to glance. For img_signature_certificate_uuid, you must specify the UUID of the signing key you previously uploaded to barbican
  output=$(openstack image create --container-format bare --disk-format qcow2 --property img_signature='$image_signature_b64' --property img_signature_certificate_uuid=$href_id --property img_signature_hash_method='SHA-256' --property img_signature_key_type='RSA-PSS' $image < $cloud_file)
  echo $output
  echo $output >> $logs_directory/creating_signed_image.log
  
  if [ $(openstack image show $image | awk '/status/ {print $4}') = 'active' ]
  then
    echo "Image Created Successfully"
    echo "Image Created Successfully" >> $logs_directory/creating_signed_image.log
  else
    echo "Image Creation Failed"
    echo "Image Creation Failed" >> $logs_directory/creating_signed_image.log
    rm -rf /home/osp_Admin/barbican_keys/*
  fi
}
###################################################################################

###################################################################################
creating_network_and_server()
{
  output=$(openstack network create $network)
  echo $output
  echo $output > $logs_directory/creating_network_and_server.log
  
  output=$(openstack subnet create $subnet --network $network --subnet-range 192.168.50.0/24)
  echo $output
  echo $output >> $logs_directory/creating_network_and_server.log
  
  output=$(openstack router create $router)
  echo $output
  echo $output >> $logs_directory/creating_network_and_server.log
  
  output=$(openstack router set $router --external-gateway $public_network)
  echo $output
  echo $output >> $logs_directory/creating_network_and_server.log
  ###Adding Private Subnet to Router
  output=$(openstack router add subnet $router $subnet)
  echo $output
  echo $output >> $logs_directory/creating_network_and_server.log
  ### creating keypair
  output=$(openstack keypair create ssh-key >> /home/osp_admin/ssh-key.pem)
  echo $output
  echo $output >> $logs_directory/creating_network_and_server.log
  chmod 400 /home/osp_admin/ssh-key.pem
  ### creating server
  output=$(openstack server create --flavor $flavor --image $image --key-name ssh-key --security-group $security_group --network $network $instance)
  echo $output
  echo $output >> $logs_directory/creating_network_and_server.log
  sleep 1m
  output=$(openstack server show $instance | grep status )
  status=$(awk '{ if($4 == "active") print $4;}' awk.txt)
  if [ $status = 'active']
  then
    echo '========================================================================================='
    echo '===================== Instance created  Created successfully ============================'
    echo '========================================================================================='
    echo '===================== Instance created  Created successfully ============================' >> $logs_directory/creating_network_and_server.log
    for i in {1};do openstack port list --server "$instance" | awk -F "|" '/-/ {print $2}' | xargs -I{} openstack floating ip create --port {} public; echo "$instance"; done
#    openstack floating ip create $public_network
#    #assign floating ip to instance
#    echo '=========== List of Floating IPs =============='
#    openstack floating ip list
#    echo 'Enter created floating ip = '
#    read Floating_IP
#    openstack server add floating ip $instance $Floating_IP
#    output=$(ping -c 1 $Floating_IP &> /dev/null && echo success || echo fail)
    Floating_IP=$(openstack server list | awk '{ if($4 == "$instance") print $10}')
    output=$(ping -c 1 $Floating_IP &> /dev/null && echo success || echo fail)
    if [ $output = 'success']
    then
      ping $Floating_IP
      echo '=========================== instance is reachable from external network ==========='
      echo '=========================== instance is reachable from external network ===========' >> $logs_directory/creating_network_and_server.log
    else 
      ping $Floating_IP
      echo '=========================== ping unsuccessfull, test case failde ==========='
      echo '=========================== ping unsuccessfull, test case failde ===========' >> $logs_directory/creating_network_and_server.log
    fi
  else
    echo '========================================================================================='
    echo '======================= Test Case Failed, Encrypted Instance not created ================'
    echo '========================================================================================='
    echo '======================= Test Case Failed, Encrypted Instance not created ================' >> $logs_directory/creating_network_and_server.log
  fi
}
###################################################################################
attach_encrypted_volume_to_existing_instance()
{
  #openstack server add volume $instance $encrypted_volume
  output=$(openstack volume create --size 5 --bootable $unencrypted_volume)
  echo $output
  echo $output >> $logs_directory/attach_encrypted_volume_to_existing_instance.log
  
  output=$(openstack server add volume $instance $unencrypted_volume)
  echo $output
  echo $output >> $logs_directory/attach_encrypted_volume_to_existing_instance.log
  if [ $(openstack server show $instance | awk '/volumes_attached/ {print $4}') = '|' ]
  then
    echo "volume Attaced failed / No volume Attached"
    echo "volume Attaced failed / No volume Attached" >> $logs_directory/attach_encrypted_volume_to_existing_instance.log
  else
    echo "Volume Attached Successfully"
    echo "Volume Attached Successfully" >> $logs_directory/attach_encrypted_volume_to_existing_instance.log
  fi
}
#############---------- Main ------------#############
# uncomment functions according to the requirement
verify_glance_with_barbican
verify_cinder_uses_barbican
verify_nova_uses_barbican
#encrypted_volume_creation
#verify_addition_of_key_to_barbican_secret_store ## this should be called in 'creating_signed_image', if needed 
#creating_signed_image
#creating_network_and_server
#attach_encrypted_volume_to_existing_instance
