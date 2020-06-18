package vaultsecret

import (
	"context"
	"fmt"

	maupuv1beta1 "github.com/nmaupu/vault-secret/pkg/apis/maupu/v1beta1"
	nmvault "github.com/nmaupu/vault-secret/pkg/vault"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const (
	ControllerName = "vaultsecret-controller"
)

var log = logf.Log.WithName(ControllerName)

// Fitlering events on labels
var LabelsFilter map[string]string

func AddLabelFilter(key, value string) {
	if LabelsFilter == nil {
		LabelsFilter = make(map[string]string)
	}

	LabelsFilter[key] = value
}

// Add creates a new VaultSecret Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileVaultSecret{client: mgr.GetClient(), scheme: mgr.GetScheme()}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New(ControllerName, mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Create a predicate to filter incoming events on configured labels filter
	pred := predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			objectLabels := e.Meta.GetLabels()
			for lfk, lfv := range LabelsFilter {
				if val, ok := objectLabels[lfk]; ok {
					if val != lfv {
						return false
					}
				} else {
					return false
				}
			}

			return true
		},
	}
	// Watch for changes to primary resource VaultSecret
	err = c.Watch(&source.Kind{Type: &maupuv1beta1.VaultSecret{}}, &handler.EnqueueRequestForObject{}, pred)
	if err != nil {
		return err
	}

	// Also watch for operator's created secrets
	err = c.Watch(&source.Kind{Type: &corev1.Secret{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &maupuv1beta1.VaultSecret{},
	}, pred)

	if err != nil {
		return err
	}

	return nil
}

var _ reconcile.Reconciler = &ReconcileVaultSecret{}

// ReconcileVaultSecret reconciles a VaultSecret object
type ReconcileVaultSecret struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client client.Client
	scheme *runtime.Scheme
}

// Reconcile reads that state of the cluster for a VaultSecret object and makes changes based on the state read
// and what is in the VaultSecret.Spec
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileVaultSecret) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling VaultSecret")

	// Fetch the VaultSecret CRInstance
	CRInstance := &maupuv1beta1.VaultSecret{}
	err := r.client.Get(context.TODO(), request.NamespacedName, CRInstance)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return reconcile.Result{}, err
	}

	// Define a new Secret object from CR specs
	secretFromCR, err := newSecretForCR(CRInstance)
	if err != nil && secretFromCR == nil {
		// An error occured, requeue
		return reconcile.Result{}, err
	} else if err != nil && secretFromCR != nil {
		// Some vault path and/or fields are not found, update CR (status) and requeue
		reqLogger.Error(err, "Some errors have been issued in the CR status information, please check")
		if updateErr := r.client.Status().Update(context.TODO(), CRInstance); updateErr != nil {
			reqLogger.Error(updateErr, "Error occured when updating CR status")
		}
		return reconcile.Result{}, err
	}

	// Everything's ok

	// Set VaultSecret CRInstance as the owner and controller
	if err = controllerutil.SetControllerReference(CRInstance, secretFromCR, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Creating or updating secret resource from CR
	// Check if this Secret already exists
	found := &corev1.Secret{}
	err = r.client.Get(context.TODO(), types.NamespacedName{Name: secretFromCR.Name, Namespace: secretFromCR.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		// Secret does not exist, creating it
		reqLogger.Info(fmt.Sprintf("Creating new Secret %s/%s", secretFromCR.Namespace, secretFromCR.Name))
		err = r.client.Create(context.TODO(), secretFromCR)
	} else {
		// Secret already exists - updating
		reqLogger.Info(fmt.Sprintf("Reconciling existing Secret %s/%s", found.Namespace, found.Name))
		err = r.client.Update(context.TODO(), secretFromCR)
	}

	// No problem creating or updating secret, updating CR info
	reqLogger.Info("Updating CR status information")
	if updateErr := r.client.Status().Update(context.TODO(), CRInstance); updateErr != nil {
		reqLogger.Error(updateErr, "Error occured when updating CR status")
	}

	// finally return giving err (nil if not problem occured, set to something otherwise)
	return reconcile.Result{}, err
}

func newSecretForCR(cr *maupuv1beta1.VaultSecret) (*corev1.Secret, error) {
	labels := map[string]string{
		"crName":      cr.Name,
		"crNamespace": cr.Namespace,
		"controller":  ControllerName,
	}
	// Adding filtered labels
	for key, val := range LabelsFilter {
		labels[key] = val
	}

	secretName := cr.Spec.SecretName
	if secretName == "" {
		secretName = cr.Name
	}

	secretType := cr.Spec.SecretType
	if secretType == "" {
		secretType = "Opaque"
	}

	for key, val := range cr.Spec.SecretLabels {
		labels[key] = val
	}

	// Authentication provider
	authProvider, err := cr.GetVaultAuthProvider()
	if err != nil {
		return nil, err
	}

	// Processing vault login
	vaultConfig := nmvault.NewVaultConfig(cr.Spec.Config.Addr)
	vaultConfig.Namespace = cr.Spec.Config.Namespace
	vaultConfig.Insecure = cr.Spec.Config.Insecure
	vclient, err := authProvider.Login(vaultConfig)
	if err != nil {
		return nil, err
	}

	// Init
	hasError := false
	secrets := map[string][]byte{}
	// Clear status slice
	cr.Status.Entries = nil
	// Creating secret data from CR
	for _, s := range cr.Spec.Secrets {
		var errMessage string
		var rootErrMessage string
		var status bool

		// Vault read
		sec, err := nmvault.Read(vclient, s.KvPath, s.Path)

		if err != nil {
			hasError = true
			if err != nil {
				rootErrMessage = err.Error()
			}
			errMessage = "Problem occured getting secret"
			status = false
		} else if sec == nil || sec[s.Field] == nil || sec[s.Field] == "" {
			hasError = true
			if err != nil {
				rootErrMessage = err.Error()
			}
			errMessage = "Secret field not found in vault"
			status = false
		} else {
			status = true
			secrets[s.SecretKey] = ([]byte)(sec[s.Field].(string))
		}

		// Updating CR Status field
		cr.Status.Entries = append(cr.Status.Entries, maupuv1beta1.VaultSecretStatusEntry{
			Secret:    s,
			Status:    status,
			Message:   errMessage,
			RootError: rootErrMessage,
		})
	}

	// Handle return
	// Error is returned along with secret if it occured at least once during loop
	// In case of error, we return a half populated secret object that caller has to handle itself
	var retErr error
	retErr = nil
	if hasError {
		retErr = fmt.Errorf("Secret %s cannot be created, see CR Status field for details", cr.Spec.SecretName)
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: cr.Namespace,
			Labels:    labels,
		},
		Data: secrets,
		Type: secretType,
	}, retErr
}
