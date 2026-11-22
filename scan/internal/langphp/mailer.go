package langphp

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

// Mail sinks: Symfony Mailer and mail(). Mail content is a delivery sink for the
// recovery claim only; it is never an output (XSS), header or request sink.

const (
	mimeEmailClass       = `Symfony\Component\Mime\Email`
	templatedEmailClass  = `Symfony\Bridge\Twig\Mime\TemplatedEmail`
	mailerInterfaceClass = `Symfony\Component\Mailer\MailerInterface`
	transportInterface   = `Symfony\Component\Mailer\Transport\TransportInterface`
	urlGeneratorClass    = `Symfony\Component\Routing\Generator\UrlGeneratorInterface`
)

// phpMailOperand is one recipient or content operand of a message.
type phpMailOperand struct {
	method string
	value  phpValue
	at     analysis.Evidence
}

// phpMail is the state of one message object.
type phpMail struct {
	recipients, content []phpMailOperand
}

// phpMailSend is one delivered message, under the entry that sends it.
type phpMailSend struct {
	entry               string
	contract            string
	recipients, content []phpMailOperand
	at                  analysis.Evidence
}

var mailRecipientMethods = map[string]bool{"to": true, "addto": true, "cc": true, "addcc": true, "bcc": true, "addbcc": true}
var mailContentMethods = map[string]bool{"html": true, "text": true, "subject": true, "context": true}

func mailClass(class string) bool {
	return strings.EqualFold(class, mimeEmailClass) || strings.EqualFold(class, templatedEmailClass)
}

// mailCreation tracks `new Email()` and `new TemplatedEmail()`.
func (f *phpFlow) mailCreation(n, clsNode *sitter.Node, cls string) (phpValue, bool) {
	if clsNode == nil {
		return phpValue{}, false
	}
	index := f.set.classIndex()
	qualified := strings.TrimPrefix(index.qualify(f.module, cls, clsNode.StartByte()), `\`)
	if !mailClass(qualified) || len(index.byName[strings.ToLower(qualified)]) > 0 {
		return phpValue{}, false
	}
	f.evalChildren(n)
	f.set.objects++
	st := f.set.accountState()
	st.mails[f.set.objects] = &phpMail{}
	return phpValue{binding: "mime_email", class: qualified, objectID: f.set.objects}, true
}

// mailerCall models message builders, the send, and URL generation that
// carries a secret into content.
func (f *phpFlow) mailerCall(n *sitter.Node, receiver phpValue, method string, values []phpValue) (phpValue, bool) {
	lower := strings.ToLower(method)
	if receiver.binding == "mime_email" {
		mail := f.set.accountState().mails[receiver.objectID]
		if mail == nil {
			return receiver, true
		}
		args := phpArgs(n)
		for i, v := range values {
			at := f.module.evidence("mail_operand", n)
			if i < len(args) {
				at = f.module.evidence("mail_operand", args[i])
			}
			switch {
			case mailRecipientMethods[lower]:
				mail.recipients = append(mail.recipients, phpMailOperand{method: method, value: v, at: at})
			case mailContentMethods[lower]:
				mail.content = append(mail.content, phpMailOperand{method: method, value: v, at: at})
			}
		}
		return receiver, true
	}
	class := strings.TrimPrefix(receiver.class, `\`)
	if lower == "send" && (strings.EqualFold(class, mailerInterfaceClass) || strings.EqualFold(class, transportInterface)) && len(values) > 0 && values[0].binding == "mime_email" {
		mail := f.set.accountState().mails[values[0].objectID]
		if mail == nil {
			return phpValue{}, true
		}
		f.mailSend(n, phpMailSend{contract: "api." + analysispacks.SymfonyMailerContract, recipients: append([]phpMailOperand{}, mail.recipients...), content: append([]phpMailOperand{}, mail.content...), at: f.module.evidence(analysis.RecoveryDeliveryKind, n)})
		return phpValue{}, true
	}
	if lower == "generatetoken" && strings.EqualFold(class, `Symfony\Component\Security\Csrf\TokenGenerator\TokenGeneratorInterface`) {
		return phpValue{secret: &phpSecret{source: f.module.evidence("secret_source", n), strength: analysis.SecretCSPRNG}, unknown: true}, true
	}
	generate := lower == "generate" && strings.EqualFold(class, urlGeneratorClass) ||
		lower == "generateurl" && phpText(f.module, phpField(n, "object")) == "$this"
	if generate && len(values) > 1 {
		if sec := secretOf(values[1]); sec != nil {
			out := sliceFrom(values, 0)
			out.secret = sec
			return out, true
		}
	}
	return phpValue{}, false
}

// phpMailCall models mail(to, subject, message) (api.php-mail-v1).
func (f *phpFlow) phpMailCall(n *sitter.Node, nodes []*sitter.Node, values []phpValue) {
	if len(values) < 3 {
		return
	}
	at := func(i int) analysis.Evidence { return f.module.evidence("mail_operand", nodes[i]) }
	f.mailSend(n, phpMailSend{
		contract:   "api." + analysispacks.PHPMailContract,
		recipients: []phpMailOperand{{method: "to", value: values[0], at: at(0)}},
		content:    []phpMailOperand{{method: "subject", value: values[1], at: at(1)}, {method: "message", value: values[2], at: at(2)}},
		at:         f.module.evidence(analysis.RecoveryDeliveryKind, n),
	})
}

// mailSend keeps the modeled send in the account state and records a
// recovery candidate when its content carries a secret.
func (f *phpFlow) mailSend(n *sitter.Node, s phpMailSend) {
	s.entry = f.entry.Name
	st := f.set.accountState()
	st.sends = append(st.sends, s)
	f.noteRecovery(n, s)
}

// secretOf finds a secret on a value or any of its fields.
func secretOf(v phpValue) *phpSecret {
	if v.secret != nil {
		return v.secret
	}
	for _, key := range sortedTwigFields(v.fields) {
		if s := secretOf(v.fields[key]); s != nil {
			return s
		}
	}
	return nil
}
