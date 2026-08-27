@load policy/tuning/json-logs

redef Site::local_nets += {
    10.10.0.0/16,
    10.255.0.0/16,
    10.50.0.0/16
};
